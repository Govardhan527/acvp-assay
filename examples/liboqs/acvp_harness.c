/*
 * acvp_harness.c -- an acvp-assay harness in C, backed by liboqs.
 *
 * The contract is the same one every harness speaks: read one JSON request per
 * line on stdin, write one JSON response per line on stdout, flush, repeat.
 * See docs/harness-protocol.md.
 *
 * This one exists because liboqs's *public* C API cannot express most of what
 * NIST's ML-DSA vectors ask for, and the code underneath it can. ACVP fixes the
 * randomness for every generation case -- d and z for an ML-KEM key pair, m for
 * an encapsulation, one seed for an ML-DSA key pair, rnd for a hedged signature
 * -- and an answer produced from randomness of the implementation's own choosing
 * matches nothing NIST recorded. So:
 *
 *   - ML-KEM is entirely answerable through OQS_KEM_*: keypair_derand takes the
 *     64-byte d||z, encaps_derand takes m, and decaps is deterministic already.
 *
 *   - ML-DSA is not. OQS_SIG_ml_dsa_* offers keypair, sign, verify and the two
 *     _with_ctx_str forms, and none of them takes a seed, an rnd, or a mu. Every
 *     keyGen case and every sigGen case in NIST's sets is therefore unreachable
 *     through that API -- not because liboqs cannot compute the answer, but
 *     because the interface has nowhere to put the inputs.
 *
 * One layer down, liboqs vendors mldsa-native, whose keypair_internal,
 * signature_internal, signature_pre_hash_internal, verify_internal and
 * verify_extmu take exactly those inputs. This harness calls them directly, and
 * says so: --interface public restricts it to OQS_SIG_* and declines everything
 * else as interface_lacks, which is how a run measures the reach of the public
 * API rather than of the library.
 *
 * Every entry point below the public API is declared __attribute__((weak)) and
 * checked before it is called. Nothing here assumes a symbol exists; a liboqs
 * built with a different backend, or an older one, declines rather than fails
 * to link. That is also why the Makefile links --whole-archive: a weak reference
 * alone does not pull an object out of a static archive, so the symbols would be
 * silently null.
 *
 * Build:
 *     make LIBOQS=/path/to/liboqs-install
 *
 * Probe what this build can reach, as machine-readable JSON:
 *     ./acvp_harness --capabilities
 *
 * Run:
 *     acvp-assay run vectors/ML-DSA-sigGen-FIPS204/prompt.json \
 *         --provider-command "./acvp_harness"
 *
 * Public domain / CC0. Copy it into your tree and edit freely.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <oqs/oqs.h>

/* liboqs installs the callback structs for these but not the prototypes of the
   functions themselves, although the symbols are exported. The signatures are
   the ones sha2_ops.h and sha3_ops.h document for their own callbacks. */
void OQS_SHA2_sha256(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA2_sha384(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA2_sha512(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen);
void OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
void OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
void OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state);
void OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input,
                                  size_t inlen);
void OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state);
void OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state);

#ifndef ACVP_LIBOQS_COMMIT
#define ACVP_LIBOQS_COMMIT ""
#endif
#ifndef ACVP_HARNESS_CC
#define ACVP_HARNESS_CC ""
#endif
#ifndef ACVP_HARNESS_CFLAGS
#define ACVP_HARNESS_CFLAGS ""
#endif

/* ------------------------------------------------------------------ buffers */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} Buf;

static void buf_reserve(Buf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap)
        return;
    size_t want = b->cap ? b->cap : 256;
    while (want < b->len + extra + 1)
        want *= 2;
    char *grown = realloc(b->data, want);
    if (!grown) {
        fprintf(stderr, "acvp_harness: out of memory\n");
        exit(1);
    }
    b->data = grown;
    b->cap = want;
}

static void buf_add(Buf *b, const char *s, size_t n)
{
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_puts(Buf *b, const char *s) { buf_add(b, s, strlen(s)); }

static void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }

/* --------------------------------------------------------------------- hex */

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex into a fresh buffer. NULL on malformed input; an empty string is
   valid and yields a zero-length buffer, which real vectors do use. */
static unsigned char *hex_decode(const char *hex, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n % 2) return NULL;
    unsigned char *out = malloc(n / 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_value(hex[i]), lo = hex_value(hex[i + 1]);
        if (hi < 0 || lo < 0) { free(out); return NULL; }
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return out;
}

static void buf_add_hex(Buf *b, const unsigned char *bytes, size_t n)
{
    static const char digits[] = "0123456789ABCDEF";
    buf_reserve(b, n * 2);
    for (size_t i = 0; i < n; i++) {
        b->data[b->len++] = digits[bytes[i] >> 4];
        b->data[b->len++] = digits[bytes[i] & 0x0F];
    }
    b->data[b->len] = '\0';
}

/* -------------------------------------------------------------------- JSON */

/* The protocol uses flat objects whose values are strings, integers or
   booleans, so a full parser would be more code than the rest of the file.
   This finds "key" at brace depth 1 and returns its value. */

static const char *find_value(const char *json, const char *key)
{
    size_t klen = strlen(key);
    int depth = 0, in_string = 0;
    for (const char *p = json; *p; p++) {
        if (in_string) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') in_string = 0;
            continue;
        }
        if (*p == '"') {
            if (depth == 1 && strncmp(p + 1, key, klen) == 0 && p[1 + klen] == '"') {
                const char *q = p + 2 + klen;
                while (*q == ' ' || *q == '\t') q++;
                if (*q != ':') { in_string = 1; continue; }
                q++;
                while (*q == ' ' || *q == '\t') q++;
                return q;
            }
            in_string = 1;
            continue;
        }
        if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') depth--;
    }
    return NULL;
}

static char *json_string(const char *json, const char *key)
{
    const char *v = find_value(json, key);
    if (!v || *v != '"') return NULL;
    v++;
    char *out = malloc(strlen(v) + 1);
    if (!out) return NULL;
    size_t n = 0;
    while (*v && *v != '"') {
        if (*v == '\\' && v[1]) {
            v++;
            switch (*v) {
            case 'n': out[n++] = '\n'; break;
            case 't': out[n++] = '\t'; break;
            case 'r': out[n++] = '\r'; break;
            default:  out[n++] = *v;   break;
            }
            v++;
            continue;
        }
        out[n++] = *v++;
    }
    out[n] = '\0';
    return out;
}

static int json_bool(const char *json, const char *key)
{
    const char *v = find_value(json, key);
    return v && strncmp(v, "true", 4) == 0;
}

/* Decode a hex string field. Sets *out_len, and returns NULL when the field is
   absent or malformed; *present says which, because an absent field and an
   empty one mean different things here. */
static unsigned char *json_bytes(const char *json, const char *key, size_t *out_len, int *present)
{
    char *hex = json_string(json, key);
    *present = hex != NULL;
    if (!hex) { *out_len = 0; return NULL; }
    unsigned char *bytes = hex_decode(hex, out_len);
    free(hex);
    return bytes;
}

/* ---------------------------------------------------------------- responses */

static void emit(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);   /* not optional: a buffered harness looks exactly like a
                         hung one to the runner */
}

static void emit_buf(Buf *b)
{
    fwrite(b->data, 1, b->len, stdout);
    putchar('\n');
    fflush(stdout);
}

/* Declining is a first-class answer, and the reason decides where a reader is
   sent. interface_lacks says the module does this and the API cannot express
   the case, which is repaired by exposing an entry point; implementation_lacks
   says it does not do it at all. Reporting the first as the second sends a
   vendor to write code they have already written. */
static void emit_declined(const char *reason, const char *detail)
{
    emit("{\"error\": \"unsupported\", \"declineReason\": \"%s\", \"detail\": \"%s\"}",
         reason, detail);
}

static void emit_interface_lacks(const char *detail) { emit_declined("interface_lacks", detail); }
static void emit_impl_lacks(const char *detail) { emit_declined("implementation_lacks", detail); }
static void emit_vector_incomplete(const char *detail)
{
    emit_declined("vector_incomplete", detail);
}

/* The operation, never the value that failed: this text reaches logs and CI
   output, and a failure message that quotes a key travels with them. */
static void emit_failure(const char *why) { emit("{\"error\": \"%s\"}", why); }

/* ------------------------------------------------- liboqs, below its API */

/* mldsa-native's internal entry points, namespaced per parameter set and per
   arithmetic backend. Weak, so a liboqs that does not carry them leaves these
   null and the operations that need them decline instead of failing to link.
   Declared here rather than included: they are not part of liboqs's installed
   headers, and this file states exactly the ABI it assumes. */
#define MLDSA_DECLARE(NS)                                                                        \
    extern int NS##_keypair_internal(uint8_t *, uint8_t *, const uint8_t *)                      \
        __attribute__((weak));                                                                   \
    extern int NS##_signature_internal(uint8_t *, size_t *, const uint8_t *, size_t,             \
                                       const uint8_t *, size_t, const uint8_t *,                 \
                                       const uint8_t *, int) __attribute__((weak));              \
    extern int NS##_signature_pre_hash_internal(uint8_t *, size_t *, const uint8_t *, size_t,    \
                                                const uint8_t *, size_t, const uint8_t *,        \
                                                const uint8_t *, int) __attribute__((weak));     \
    extern int NS##_verify_internal(const uint8_t *, size_t, const uint8_t *, size_t,            \
                                    const uint8_t *, size_t, const uint8_t *, int)               \
        __attribute__((weak));                                                                   \
    extern int NS##_verify_pre_hash_internal(const uint8_t *, size_t, const uint8_t *, size_t,   \
                                             const uint8_t *, size_t, const uint8_t *, int)      \
        __attribute__((weak));

MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA44_C)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA44_X86_64)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA44_AARCH64)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA65_C)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA65_X86_64)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA65_AARCH64)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA87_C)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA87_X86_64)
MLDSA_DECLARE(PQCP_MLDSA_NATIVE_MLDSA87_AARCH64)

typedef int (*keypair_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*sign_fn)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t,
                       const uint8_t *, const uint8_t *, int);
typedef int (*pre_hash_sign_fn)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *,
                                size_t, const uint8_t *, const uint8_t *, int);
typedef int (*verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                         size_t, const uint8_t *, int);
typedef int (*pre_hash_verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t,
                                  const uint8_t *, size_t, const uint8_t *, int);

/* liboqs picks its ML-DSA and ML-KEM backend from the CPU at run time when it is
   built OQS_DIST_BUILD, which the distributed builds are. Mirroring that rule
   here is not an optimisation: calling the portable C entry point on a machine
   where liboqs itself would have called the AVX2 one would measure code the
   library does not run. */
static int wants_x86_64(void)
{
#if defined(OQS_DIST_BUILD)
    return OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) &&
           OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
           OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT);
#else
    return 0;
#endif
}

static int wants_aarch64(void)
{
#if defined(OQS_DIST_BUILD)
    return OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON);
#else
    return 0;
#endif
}

/* Choose the variant liboqs would choose, falling back to whichever exists. */
#define MLDSA_PICK(SET, FIELD)                                                                  \
    (wants_x86_64() && PQCP_MLDSA_NATIVE_MLDSA##SET##_X86_64_##FIELD                             \
         ? PQCP_MLDSA_NATIVE_MLDSA##SET##_X86_64_##FIELD                                         \
     : wants_aarch64() && PQCP_MLDSA_NATIVE_MLDSA##SET##_AARCH64_##FIELD                         \
         ? PQCP_MLDSA_NATIVE_MLDSA##SET##_AARCH64_##FIELD                                        \
         : PQCP_MLDSA_NATIVE_MLDSA##SET##_C_##FIELD)

typedef struct {
    const char *name;
    size_t      public_key;
    size_t      secret_key;
    size_t      signature;
    keypair_fn         keypair_internal;
    sign_fn            sign_internal;
    pre_hash_sign_fn   sign_pre_hash;
    verify_fn          verify_internal;
    pre_hash_verify_fn verify_pre_hash;
    OQS_STATUS (*verify_ctx)(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
                             size_t, const uint8_t *);
} MlDsaSet;

static const MlDsaSet *ml_dsa_set(const char *name)
{
    static MlDsaSet sets[3];
    static int      built = 0;
    if (!built) {
        sets[0] = (MlDsaSet){"ML-DSA-44",
                             OQS_SIG_ml_dsa_44_length_public_key,
                             OQS_SIG_ml_dsa_44_length_secret_key,
                             OQS_SIG_ml_dsa_44_length_signature,
                             MLDSA_PICK(44, keypair_internal),
                             MLDSA_PICK(44, signature_internal),
                             MLDSA_PICK(44, signature_pre_hash_internal),
                             MLDSA_PICK(44, verify_internal),
                             MLDSA_PICK(44, verify_pre_hash_internal),
                             OQS_SIG_ml_dsa_44_verify_with_ctx_str};
        sets[1] = (MlDsaSet){"ML-DSA-65",
                             OQS_SIG_ml_dsa_65_length_public_key,
                             OQS_SIG_ml_dsa_65_length_secret_key,
                             OQS_SIG_ml_dsa_65_length_signature,
                             MLDSA_PICK(65, keypair_internal),
                             MLDSA_PICK(65, signature_internal),
                             MLDSA_PICK(65, signature_pre_hash_internal),
                             MLDSA_PICK(65, verify_internal),
                             MLDSA_PICK(65, verify_pre_hash_internal),
                             OQS_SIG_ml_dsa_65_verify_with_ctx_str};
        sets[2] = (MlDsaSet){"ML-DSA-87",
                             OQS_SIG_ml_dsa_87_length_public_key,
                             OQS_SIG_ml_dsa_87_length_secret_key,
                             OQS_SIG_ml_dsa_87_length_signature,
                             MLDSA_PICK(87, keypair_internal),
                             MLDSA_PICK(87, signature_internal),
                             MLDSA_PICK(87, signature_pre_hash_internal),
                             MLDSA_PICK(87, verify_internal),
                             MLDSA_PICK(87, verify_pre_hash_internal),
                             OQS_SIG_ml_dsa_87_verify_with_ctx_str};
        built = 1;
    }
    for (size_t i = 0; i < 3; i++)
        if (!strcmp(sets[i].name, name)) return &sets[i];
    return NULL;
}

/* The ML-KEM side needs no such reaching: keypair_derand and encaps_derand take
   exactly the seeds ACVP supplies, and both are OQS_API. */
static OQS_KEM *ml_kem_new(const char *name)
{
    if (!strcmp(name, "ML-KEM-512"))  return OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (!strcmp(name, "ML-KEM-768"))  return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!strcmp(name, "ML-KEM-1024")) return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    return NULL;
}

static OQS_STATUS ml_kem_keypair_derand(const char *name, uint8_t *pk, uint8_t *sk,
                                        const uint8_t *seed)
{
    if (!strcmp(name, "ML-KEM-512"))  return OQS_KEM_ml_kem_512_keypair_derand(pk, sk, seed);
    if (!strcmp(name, "ML-KEM-768"))  return OQS_KEM_ml_kem_768_keypair_derand(pk, sk, seed);
    return OQS_KEM_ml_kem_1024_keypair_derand(pk, sk, seed);
}

static OQS_STATUS ml_kem_encaps_derand(const char *name, uint8_t *ct, uint8_t *ss,
                                       const uint8_t *pk, const uint8_t *seed)
{
    if (!strcmp(name, "ML-KEM-512"))  return OQS_KEM_ml_kem_512_encaps_derand(ct, ss, pk, seed);
    if (!strcmp(name, "ML-KEM-768"))  return OQS_KEM_ml_kem_768_encaps_derand(ct, ss, pk, seed);
    return OQS_KEM_ml_kem_1024_encaps_derand(ct, ss, pk, seed);
}

/* ---------------------------------------------------------- the pre-hashes */

/* FIPS 204's HashML-DSA hashes the message and signs an OID that names which
   hash was used, so the same digest under two names is two signatures. The
   integers are mldsa-native's MLD_PREHASH_* constants; they are an internal
   ABI and are asserted against NIST's own answers rather than trusted. */
typedef struct {
    const char *name;
    int         id;
    size_t      length;
} PreHash;

static const PreHash PRE_HASHES[] = {
    {"SHA2-256",  2, 32}, {"SHA2-384",  3, 48}, {"SHA2-512",   4, 64},
    {"SHA3-256",  8, 32}, {"SHA3-384",  9, 48}, {"SHA3-512",  10, 64},
    {"SHAKE-128", 11, 32}, {"SHAKE-256", 12, 64},
};

/* ACVP also asks for SHA2-224, SHA2-512/224, SHA2-512/256 and SHA3-224. liboqs
   exposes none of them, and this harness computes nothing liboqs does not: a
   digest written here would be this file under test rather than the library,
   and a wrong one would report a conforming module as broken. Those cases are
   declined by name. */
static const PreHash *pre_hash(const char *name)
{
    for (size_t i = 0; i < sizeof PRE_HASHES / sizeof *PRE_HASHES; i++)
        if (!strcmp(PRE_HASHES[i].name, name)) return &PRE_HASHES[i];
    return NULL;
}

static void digest_with(const PreHash *hash, const unsigned char *message, size_t length,
                        unsigned char *out)
{
    switch (hash->id) {
    case 2:  OQS_SHA2_sha256(out, message, length); break;
    case 3:  OQS_SHA2_sha384(out, message, length); break;
    case 4:  OQS_SHA2_sha512(out, message, length); break;
    case 8:  OQS_SHA3_sha3_256(out, message, length); break;
    case 9:  OQS_SHA3_sha3_384(out, message, length); break;
    case 10: OQS_SHA3_sha3_512(out, message, length); break;
    case 11: OQS_SHA3_shake128(out, hash->length, message, length); break;
    default: OQS_SHA3_shake256(out, hash->length, message, length); break;
    }
}

/* ---------------------------------------------------------------- interface */

/* Which layer of liboqs this run is allowed to reach. `public` measures the
   reach of OQS_SIG_* and OQS_KEM_* alone, which is the number a caller who can
   only link against the published API actually gets; `extended` also uses the
   entry points underneath, which is what liboqs can answer. Running both and
   diffing the reports is the point of having the switch. */
typedef enum { INTERFACE_PUBLIC, INTERFACE_EXTENDED } Interface;

static Interface interface_mode = INTERFACE_EXTENDED;

static const char *interface_name(void)
{
    return interface_mode == INTERFACE_PUBLIC ? "public" : "extended";
}

/* ---------------------------------------------------------------- metadata */

/* The harness is statically linked against liboqs, so a hash of this executable
   changes whenever either of them does. That is a stronger build identity than
   a version -- two builds a commit apart share a version -- and it needs nothing
   from the vendor, which is the point made in docs/harness-protocol.md about
   where a buildId can come from. */
static int self_build_id(char *out, size_t size)
{
    FILE *self = fopen("/proc/self/exe", "rb");
    if (!self) return 0;
    OQS_SHA3_sha3_256_inc_ctx state;
    OQS_SHA3_sha3_256_inc_init(&state);
    unsigned char chunk[65536];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, self)) > 0)
        OQS_SHA3_sha3_256_inc_absorb(&state, chunk, got);
    fclose(self);
    unsigned char digest[32];
    OQS_SHA3_sha3_256_inc_finalize(digest, &state);
    OQS_SHA3_sha3_256_inc_ctx_release(&state);

    static const char hex[] = "0123456789abcdef";
    if (size < 7 + 64 + 1) return 0;
    memcpy(out, "sha3-256:", 9);
    for (size_t i = 0; i < 32; i++) {
        out[9 + 2 * i]     = hex[digest[i] >> 4];
        out[9 + 2 * i + 1] = hex[digest[i] & 0x0F];
    }
    out[9 + 64] = '\0';
    return 1;
}

static const char *backend_dispatch(void)
{
    if (wants_x86_64())  return "x86_64";
    if (wants_aarch64()) return "aarch64";
    return "portable C";
}

static void cpu_description(char *out, size_t size)
{
    snprintf(out, size, "%s%s%s%s", backend_dispatch(),
             OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) ? " avx2" : "",
             OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) ? " bmi2" : "",
             OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT) ? " popcnt" : "");
}

static void os_description(char *out, size_t size)
{
    struct utsname host;
    if (uname(&host) == 0)
        snprintf(out, size, "%s %s %s", host.sysname, host.release, host.machine);
    else
        snprintf(out, size, "unknown");
}

static void op_metadata(void)
{
    char build_id[128], cpu[128], os[256];
    char version[128];
    if (ACVP_LIBOQS_COMMIT[0])
        snprintf(version, sizeof version, "%s (%s)", OQS_VERSION_TEXT, ACVP_LIBOQS_COMMIT);
    else
        snprintf(version, sizeof version, "%s", OQS_VERSION_TEXT);
    cpu_description(cpu, sizeof cpu);
    os_description(os, sizeof os);

    Buf out = {0};
    buf_puts(&out, "{\"name\": \"liboqs-acvp-harness\", \"libraryName\": \"liboqs\"");
    buf_puts(&out, ", \"libraryVersion\": \"");
    buf_puts(&out, version);
    buf_puts(&out, "\", \"backendName\": \"mlkem-native / mldsa-native, ");
    buf_puts(&out, interface_name());
    buf_puts(&out, " interface\", \"backendVersion\": \"");
    buf_puts(&out, backend_dispatch());
    buf_puts(&out, "\", ");
    if (self_build_id(build_id, sizeof build_id)) {
        /* A hash of the linked executable: it moves when liboqs moves. */
        buf_puts(&out, "\"buildId\": \"");
        buf_puts(&out, build_id);
        buf_puts(&out, "\"");
    } else {
        /* Nothing here can establish which build answered: not the version,
           which every build of a release shares, and not the executable, which
           could not be read. Saying so is the honest answer. */
        buf_puts(&out, "\"buildId\": null, \"buildIdAbsentReason\": \"not_recorded\"");
    }
    buf_puts(&out, ", \"build\": {\"compiler\": \"");
    buf_puts(&out, ACVP_HARNESS_CC);
    buf_puts(&out, "\", \"flags\": \"");
    buf_puts(&out, ACVP_HARNESS_CFLAGS);
    buf_puts(&out, "\", \"cpu\": \"");
    buf_puts(&out, cpu);
    buf_puts(&out, "\", \"os\": \"");
    buf_puts(&out, os);
    buf_puts(&out, "\"}}");
    emit_buf(&out);
    buf_free(&out);
}

/* -------------------------------------------------------------- ML-KEM ops */

static void op_ml_kem_keygen(const char *line)
{
    char *set = json_string(line, "parameterSet");
    size_t d_len = 0, z_len = 0;
    int have_d = 0, have_z = 0;
    unsigned char *d = json_bytes(line, "d", &d_len, &have_d);
    unsigned char *z = json_bytes(line, "z", &z_len, &have_z);
    OQS_KEM *kem = set ? ml_kem_new(set) : NULL;

    if (!kem) emit_impl_lacks("this liboqs build has no such ML-KEM parameter set");
    else if (!have_d || !have_z || d_len != 32 || z_len != 32)
        emit_vector_incomplete("an ML-KEM key pair needs a 32-byte d and z");
    else {
        uint8_t seed[64];
        memcpy(seed, d, 32);
        memcpy(seed + 32, z, 32);   /* FIPS 203 KeyGen(d, z); liboqs takes d||z */
        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        if (!pk || !sk) emit_failure("out of memory");
        else if (ml_kem_keypair_derand(set, pk, sk, seed) != OQS_SUCCESS)
            emit_failure("keypair_derand failed");
        else {
            Buf out = {0};
            buf_puts(&out, "{\"ek\": \"");
            buf_add_hex(&out, pk, kem->length_public_key);
            buf_puts(&out, "\", \"dk\": \"");
            buf_add_hex(&out, sk, kem->length_secret_key);
            buf_puts(&out, "\"}");
            emit_buf(&out);
            buf_free(&out);
        }
        free(pk); free(sk);
    }
    OQS_KEM_free(kem);
    free(set); free(d); free(z);
}

static void op_ml_kem_encapsulate(const char *line)
{
    char *set = json_string(line, "parameterSet");
    size_t ek_len = 0, m_len = 0;
    int have_ek = 0, have_m = 0;
    unsigned char *ek = json_bytes(line, "ek", &ek_len, &have_ek);
    unsigned char *m  = json_bytes(line, "m", &m_len, &have_m);
    OQS_KEM *kem = set ? ml_kem_new(set) : NULL;

    if (!kem) emit_impl_lacks("this liboqs build has no such ML-KEM parameter set");
    else if (!have_ek || !have_m || m_len != 32)
        emit_vector_incomplete("an encapsulation needs ek and a 32-byte m");
    else if (ek_len != kem->length_public_key)
        /* A deliberately malformed key: encapsulating would read past it. */
        emit_failure("encapsulation key is the wrong length");
    else {
        uint8_t *ct = malloc(kem->length_ciphertext);
        uint8_t *ss = malloc(kem->length_shared_secret);
        if (!ct || !ss) emit_failure("out of memory");
        else if (ml_kem_encaps_derand(set, ct, ss, ek, m) != OQS_SUCCESS)
            emit_failure("encaps_derand failed");
        else {
            Buf out = {0};
            buf_puts(&out, "{\"c\": \"");
            buf_add_hex(&out, ct, kem->length_ciphertext);
            buf_puts(&out, "\", \"k\": \"");
            buf_add_hex(&out, ss, kem->length_shared_secret);
            buf_puts(&out, "\"}");
            emit_buf(&out);
            buf_free(&out);
        }
        free(ct); free(ss);
    }
    OQS_KEM_free(kem);
    free(set); free(ek); free(m);
}

static void op_ml_kem_decapsulate(const char *line)
{
    char *set = json_string(line, "parameterSet");
    size_t dk_len = 0, c_len = 0;
    int have_dk = 0, have_c = 0;
    unsigned char *dk = json_bytes(line, "dk", &dk_len, &have_dk);
    unsigned char *c  = json_bytes(line, "c", &c_len, &have_c);
    OQS_KEM *kem = set ? ml_kem_new(set) : NULL;

    if (!kem) emit_impl_lacks("this liboqs build has no such ML-KEM parameter set");
    else if (!have_dk || !have_c) emit_vector_incomplete("a decapsulation needs dk and c");
    else if (dk_len != kem->length_secret_key || c_len != kem->length_ciphertext)
        emit_failure("decapsulation input is the wrong length");
    else {
        uint8_t *ss = malloc(kem->length_shared_secret);
        if (!ss) emit_failure("out of memory");
        else if (OQS_KEM_decaps(kem, ss, c, dk) != OQS_SUCCESS)
            emit_failure("decaps failed");
        else {
            Buf out = {0};
            buf_puts(&out, "{\"k\": \"");
            buf_add_hex(&out, ss, kem->length_shared_secret);
            buf_puts(&out, "\"}");
            emit_buf(&out);
            buf_free(&out);
        }
        free(ss);
    }
    OQS_KEM_free(kem);
    free(set); free(dk); free(c);
}

/* ACVP's key-check groups are half well-formed keys and half deliberately
   malformed ones, and rejecting the malformed half is the correct answer.
   liboqs has no key-check entry point, so the check is the operation the key is
   for: encapsulating under it, or decapsulating with it. Both reject exactly
   the keys NIST records as invalid, so the verdict is the library's own. */
static void op_ml_kem_key_check(const char *line)
{
    char *set = json_string(line, "parameterSet");
    char *type = json_string(line, "keyType");
    size_t key_len = 0;
    int have_key = 0;
    unsigned char *key = json_bytes(line, "key", &key_len, &have_key);
    OQS_KEM *kem = set ? ml_kem_new(set) : NULL;

    if (!kem) emit_impl_lacks("this liboqs build has no such ML-KEM parameter set");
    else if (!have_key || !type) emit_vector_incomplete("a key check needs key and keyType");
    else {
        int encapsulation = !strcmp(type, "ek");
        size_t wanted = encapsulation ? kem->length_public_key : kem->length_secret_key;
        int accepted = key_len == wanted;
        if (accepted) {
            uint8_t *ct = malloc(kem->length_ciphertext);
            uint8_t *ss = malloc(kem->length_shared_secret);
            if (!ct || !ss) { free(ct); free(ss); accepted = 0; }
            else {
                if (encapsulation) {
                    uint8_t seed[32] = {0};
                    accepted = ml_kem_encaps_derand(set, ct, ss, key, seed) == OQS_SUCCESS;
                } else {
                    memset(ct, 0, kem->length_ciphertext);
                    accepted = OQS_KEM_decaps(kem, ss, ct, key) == OQS_SUCCESS;
                }
                free(ct); free(ss);
            }
        }
        emit("{\"testPassed\": %s}", accepted ? "true" : "false");
    }
    OQS_KEM_free(kem);
    free(set); free(type); free(key);
}

/* -------------------------------------------------------------- ML-DSA ops */

static void op_ml_dsa_keygen(const char *line)
{
    char *name = json_string(line, "parameterSet");
    size_t seed_len = 0;
    int have_seed = 0;
    unsigned char *seed = json_bytes(line, "seed", &seed_len, &have_seed);
    const MlDsaSet *set = name ? ml_dsa_set(name) : NULL;

    if (!set) emit_impl_lacks("this liboqs build has no such ML-DSA parameter set");
    else if (!have_seed || seed_len != 32)
        emit_vector_incomplete("an ML-DSA key pair needs a 32-byte seed");
    else if (interface_mode == INTERFACE_PUBLIC)
        /* OQS_SIG_ml_dsa_*_keypair draws its own randomness and returns a key
           pair unrelated to the vector. The library derives from a seed on
           every call; the API has nowhere to pass one in. */
        emit_interface_lacks("OQS_SIG_ml_dsa_keypair takes no seed");
    else if (!set->keypair_internal)
        emit_impl_lacks("this liboqs build exposes no seeded ML-DSA key generation");
    else {
        uint8_t *pk = malloc(set->public_key);
        uint8_t *sk = malloc(set->secret_key);
        if (!pk || !sk) emit_failure("out of memory");
        else if (set->keypair_internal(pk, sk, seed) != 0)
            emit_failure("keypair_internal failed");
        else {
            Buf out = {0};
            buf_puts(&out, "{\"pk\": \"");
            buf_add_hex(&out, pk, set->public_key);
            buf_puts(&out, "\", \"sk\": \"");
            buf_add_hex(&out, sk, set->secret_key);
            buf_puts(&out, "\"}");
            emit_buf(&out);
            buf_free(&out);
        }
        free(pk); free(sk);
    }
    free(name); free(seed);
}

/* The prefix the external interface signs over: 00 for pure ML-DSA, 01 for
   HashML-DSA, then one byte of context length, then the context. The internal
   interface signs no prefix at all, which is not the same as an empty one. */
static size_t build_prefix(unsigned char *prefix, int pre_hashed,
                           const unsigned char *context, size_t context_len)
{
    prefix[0] = pre_hashed ? 1 : 0;
    prefix[1] = (unsigned char)context_len;
    memcpy(prefix + 2, context, context_len);
    return 2 + context_len;
}

static void op_ml_dsa_sign(const char *line)
{
    char *name = json_string(line, "parameterSet");
    char *interface = json_string(line, "signatureInterface");
    char *pre_hash_mode = json_string(line, "preHash");
    char *hash_alg = json_string(line, "hashAlg");
    int external_mu = json_bool(line, "externalMu");
    int deterministic = json_bool(line, "deterministic");

    size_t sk_len = 0, msg_len = 0, ctx_len = 0, rnd_len = 0;
    int have_sk = 0, have_msg = 0, have_ctx = 0, have_rnd = 0;
    unsigned char *sk  = json_bytes(line, "sk", &sk_len, &have_sk);
    unsigned char *msg = json_bytes(line, external_mu ? "mu" : "message", &msg_len, &have_msg);
    unsigned char *ctx = json_bytes(line, "context", &ctx_len, &have_ctx);
    unsigned char *rnd = json_bytes(line, "rnd", &rnd_len, &have_rnd);

    const MlDsaSet *set = name ? ml_dsa_set(name) : NULL;
    int internal = interface && !strcmp(interface, "internal");
    int pre_hashed = pre_hash_mode && !strcmp(pre_hash_mode, "preHash");
    /* A deterministic case signs with 32 zero bytes. FIPS 204 says so, and the
       alternative reading -- pick your own -- produces a valid signature that
       matches nothing. */
    unsigned char zero_rnd[32] = {0};
    const unsigned char *randomness = have_rnd ? rnd : zero_rnd;

    if (!set) emit_impl_lacks("this liboqs build has no such ML-DSA parameter set");
    else if (!have_sk || !have_msg || sk_len != set->secret_key)
        emit_vector_incomplete("a signature needs sk and a message or mu");
    else if (!deterministic && (!have_rnd || rnd_len != 32))
        emit_vector_incomplete("a hedged case needs a 32-byte rnd");
    else if (external_mu && msg_len != 64)
        emit_vector_incomplete("an externalMu case needs a 64-byte mu");
    else if (ctx_len > 255)
        emit_vector_incomplete("a context longer than 255 bytes has no encoding here");
    else if (interface_mode == INTERFACE_PUBLIC)
        /* OQS_SIG_ml_dsa_*_sign and _sign_with_ctx_str hedge with randomness
           they draw themselves, and neither takes an rnd or a mu. Nothing in
           the published API can answer a sigGen case, deterministic or not. */
        emit_interface_lacks("OQS_SIG_ml_dsa_sign takes no rnd, so no sigGen case is comparable");
    else if (pre_hashed && !set->sign_pre_hash)
        emit_impl_lacks("this liboqs build exposes no HashML-DSA signing");
    else if (!pre_hashed && !set->sign_internal)
        emit_impl_lacks("this liboqs build exposes no seeded ML-DSA signing");
    else if (pre_hashed && (!hash_alg || !pre_hash(hash_alg)))
        /* liboqs offers SHA2-256/384/512, SHA3-256/384/512, SHAKE-128/256 and
           no others. Computing the missing four here would put this file under
           test instead of the library. */
        emit_impl_lacks("liboqs exposes no such hash for HashML-DSA");
    else {
        uint8_t *signature = malloc(set->signature);
        size_t   signature_len = 0;
        int rc = -1;
        if (!signature) emit_failure("out of memory");
        else if (pre_hashed) {
            const PreHash *hash = pre_hash(hash_alg);
            unsigned char digest[64];
            digest_with(hash, msg, msg_len, digest);
            rc = set->sign_pre_hash(signature, &signature_len, digest, hash->length, ctx,
                                    ctx_len, randomness, sk, hash->id);
        } else if (internal) {
            /* No prefix, and externalMu means the message is already mu. */
            rc = set->sign_internal(signature, &signature_len, msg, msg_len, NULL, 0,
                                    randomness, sk, external_mu);
        } else {
            unsigned char prefix[2 + 255];
            size_t prefix_len = build_prefix(prefix, 0, ctx, ctx_len);
            rc = set->sign_internal(signature, &signature_len, msg, msg_len, prefix, prefix_len,
                                    randomness, sk, 0);
        }
        if (signature && rc != 0) emit_failure("signing failed");
        else if (signature) {
            Buf out = {0};
            buf_puts(&out, "{\"signature\": \"");
            buf_add_hex(&out, signature, signature_len);
            buf_puts(&out, "\"}");
            emit_buf(&out);
            buf_free(&out);
        }
        free(signature);
    }
    free(name); free(interface); free(pre_hash_mode); free(hash_alg);
    free(sk); free(msg); free(ctx); free(rnd);
}

static void op_ml_dsa_verify(const char *line)
{
    char *name = json_string(line, "parameterSet");
    char *interface = json_string(line, "signatureInterface");
    char *pre_hash_mode = json_string(line, "preHash");
    char *hash_alg = json_string(line, "hashAlg");
    int external_mu = json_bool(line, "externalMu");

    size_t pk_len = 0, msg_len = 0, sig_len = 0, ctx_len = 0;
    int have_pk = 0, have_msg = 0, have_sig = 0, have_ctx = 0;
    unsigned char *pk  = json_bytes(line, "pk", &pk_len, &have_pk);
    unsigned char *msg = json_bytes(line, external_mu ? "mu" : "message", &msg_len, &have_msg);
    unsigned char *sig = json_bytes(line, "signature", &sig_len, &have_sig);
    unsigned char *ctx = json_bytes(line, "context", &ctx_len, &have_ctx);

    const MlDsaSet *set = name ? ml_dsa_set(name) : NULL;
    int internal = interface && !strcmp(interface, "internal");
    int pre_hashed = pre_hash_mode && !strcmp(pre_hash_mode, "preHash");
    int verdict = 0;

    if (!set) emit_impl_lacks("this liboqs build has no such ML-DSA parameter set");
    else if (!have_pk || !have_msg || !have_sig)
        emit_vector_incomplete("a verification needs pk, a message or mu, and a signature");
    else if (ctx_len > 255)
        emit_vector_incomplete("a context longer than 255 bytes has no encoding here");
    else if (pk_len != set->public_key || sig_len != set->signature)
        /* ACVP's sigVer sets carry deliberately wrong lengths; rejecting one is
           the correct verdict rather than an error. */
        emit("{\"testPassed\": false}");
    else if (!internal && !pre_hashed && interface_mode == INTERFACE_PUBLIC) {
        /* The one sigVer shape the published API does answer. */
        verdict = set->verify_ctx(msg, msg_len, sig, sig_len, ctx, ctx_len, pk) == OQS_SUCCESS;
        emit("{\"testPassed\": %s}", verdict ? "true" : "false");
    } else if (interface_mode == INTERFACE_PUBLIC)
        emit_interface_lacks(
            "OQS_SIG_ml_dsa_verify_with_ctx_str takes no mu and no pre-hash OID");
    else if (pre_hashed && (!hash_alg || !pre_hash(hash_alg)))
        emit_impl_lacks("liboqs exposes no such hash for HashML-DSA");
    else if (pre_hashed && !set->verify_pre_hash)
        emit_impl_lacks("this liboqs build exposes no HashML-DSA verification");
    else if (!pre_hashed && !set->verify_internal)
        emit_impl_lacks("this liboqs build exposes no internal ML-DSA verification");
    else if (pre_hashed) {
        const PreHash *hash = pre_hash(hash_alg);
        unsigned char digest[64];
        digest_with(hash, msg, msg_len, digest);
        verdict = set->verify_pre_hash(sig, sig_len, digest, hash->length, ctx, ctx_len, pk,
                                       hash->id) == 0;
        emit("{\"testPassed\": %s}", verdict ? "true" : "false");
    } else if (internal) {
        if (external_mu && msg_len != 64)
            emit_vector_incomplete("an externalMu case needs a 64-byte mu");
        else {
            verdict = set->verify_internal(sig, sig_len, msg, msg_len, NULL, 0, pk,
                                           external_mu) == 0;
            emit("{\"testPassed\": %s}", verdict ? "true" : "false");
        }
    } else {
        unsigned char prefix[2 + 255];
        size_t prefix_len = build_prefix(prefix, 0, ctx, ctx_len);
        verdict = set->verify_internal(sig, sig_len, msg, msg_len, prefix, prefix_len, pk, 0) == 0;
        emit("{\"testPassed\": %s}", verdict ? "true" : "false");
    }
    free(name); free(interface); free(pre_hash_mode); free(hash_alg);
    free(pk); free(msg); free(sig); free(ctx);
}

/* ------------------------------------------------------------ capabilities */

/* What this build of liboqs actually exposes, as JSON, established by looking
   rather than by assuming: every entry point is a weak symbol, so a null one is
   a fact about the library in front of us and not a guess. Written before any
   test logic was, and kept because the answer differs between liboqs releases,
   between backends, and between a shared and a static link. */
static void print_capabilities(void)
{
    Buf out = {0};
    char cpu[128], os[256], build_id[128];
    cpu_description(cpu, sizeof cpu);
    os_description(os, sizeof os);

    buf_puts(&out, "{\n  \"probe\": \"examples/liboqs/acvp_harness.c --capabilities\",\n");
    buf_puts(&out, "  \"library\": {\"name\": \"liboqs\", \"version\": \"" OQS_VERSION_TEXT "\"");
    if (ACVP_LIBOQS_COMMIT[0]) {
        buf_puts(&out, ", \"commit\": \"" ACVP_LIBOQS_COMMIT "\"");
    }
    buf_puts(&out, "},\n");
    buf_puts(&out, "  \"build\": {\"compiler\": \"" ACVP_HARNESS_CC "\", \"flags\": \""
                   ACVP_HARNESS_CFLAGS "\", \"cpu\": \"");
    buf_puts(&out, cpu);
    buf_puts(&out, "\", \"os\": \"");
    buf_puts(&out, os);
    buf_puts(&out, "\", \"dispatch\": \"");
    buf_puts(&out, backend_dispatch());
    buf_puts(&out, "\"},\n");
    if (self_build_id(build_id, sizeof build_id)) {
        buf_puts(&out, "  \"buildId\": \"");
        buf_puts(&out, build_id);
        buf_puts(&out, "\",\n");
    }

    buf_puts(&out, "  \"mlKem\": {\n");
    const char *kem_names[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (size_t i = 0; i < 3; i++) {
        OQS_KEM *kem = ml_kem_new(kem_names[i]);
        buf_puts(&out, "    \"");
        buf_puts(&out, kem_names[i]);
        buf_puts(&out, "\": {\"present\": ");
        buf_puts(&out, kem ? "true" : "false");
        /* Both are OQS_API in every liboqs that has ML-KEM at all, so the
           interesting fact is that they exist rather than which layer they
           are on: the whole family is answerable from the published API. */
        buf_puts(&out, ", \"keypairDerand\": \"public\", \"encapsDerand\": \"public\"");
        buf_puts(&out, ", \"decaps\": \"public\", \"keyCheck\": \"via encaps/decaps\"}");
        buf_puts(&out, i == 2 ? "\n" : ",\n");
        OQS_KEM_free(kem);
    }
    buf_puts(&out, "  },\n  \"mlDsa\": {\n");
    const char *dsa_names[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    for (size_t i = 0; i < 3; i++) {
        const MlDsaSet *set = ml_dsa_set(dsa_names[i]);
        buf_puts(&out, "    \"");
        buf_puts(&out, dsa_names[i]);
        buf_puts(&out, "\": {");
        buf_puts(&out, "\"keypairFromSeed\": \"");
        buf_puts(&out, set && set->keypair_internal ? "internal" : "absent");
        buf_puts(&out, "\", \"signWithRnd\": \"");
        buf_puts(&out, set && set->sign_internal ? "internal" : "absent");
        buf_puts(&out, "\", \"signExternalMu\": \"");
        buf_puts(&out, set && set->sign_internal ? "internal" : "absent");
        buf_puts(&out, "\", \"signPreHash\": \"");
        buf_puts(&out, set && set->sign_pre_hash ? "internal" : "absent");
        buf_puts(&out, "\", \"verifyInternal\": \"");
        buf_puts(&out, set && set->verify_internal ? "internal" : "absent");
        buf_puts(&out, "\", \"verifyPreHash\": \"");
        buf_puts(&out, set && set->verify_pre_hash ? "internal" : "absent");
        buf_puts(&out, "\", \"verifyPureExternal\": \"public\"");
        buf_puts(&out, ", \"keypairSeeded_public\": false, \"signWithRnd_public\": false}");
        buf_puts(&out, i == 2 ? "\n" : ",\n");
    }
    buf_puts(&out, "  },\n  \"preHash\": {\"available\": [");
    for (size_t i = 0; i < sizeof PRE_HASHES / sizeof *PRE_HASHES; i++) {
        buf_puts(&out, i ? ", \"" : "\"");
        buf_puts(&out, PRE_HASHES[i].name);
        buf_puts(&out, "\"");
    }
    buf_puts(&out, "],\n    \"absent\": [\"SHA2-224\", \"SHA2-512/224\", \"SHA2-512/256\", "
                   "\"SHA3-224\"],\n");
    buf_puts(&out, "    \"note\": \"liboqs exposes no SHA2-224, SHA2-512/224, SHA2-512/256 or "
                   "SHA3-224; this harness computes nothing liboqs does not, so HashML-DSA "
                   "cases naming them are declined\"}\n}");
    emit_buf(&out);
    buf_free(&out);
}

/* ---------------------------------------------------------------------- main */

static void usage(void)
{
    fprintf(stderr,
        "usage: acvp_harness [--interface public|extended] [--capabilities]\n"
        "\n"
        "Reads one JSON request per line on stdin and writes one response per\n"
        "line on stdout. Intended to be run by acvp-assay --provider-command.\n"
        "\n"
        "--interface public restricts this harness to OQS_KEM_* and OQS_SIG_*,\n"
        "which is the reach a caller linking against liboqs's published API\n"
        "gets. Every ML-DSA keyGen and sigGen case is then declined as\n"
        "interface_lacks, because that API takes no seed and no rnd. The\n"
        "default, extended, also uses the mldsa-native entry points underneath,\n"
        "which take both. Running one of each and diffing the reports is the\n"
        "measurement this harness exists to make.\n"
        "\n"
        "--capabilities prints what this build exposes, as JSON, and exits.\n");
}

int main(int argc, char **argv)
{
    int capabilities = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--capabilities")) capabilities = 1;
        else if (!strcmp(argv[i], "--interface") && i + 1 < argc) {
            const char *mode = argv[++i];
            if (!strcmp(mode, "public")) interface_mode = INTERFACE_PUBLIC;
            else if (!strcmp(mode, "extended")) interface_mode = INTERFACE_EXTENDED;
            else { usage(); return 2; }
        } else { usage(); return 2; }
    }

    if (capabilities) {
        print_capabilities();
        return 0;
    }

    char  *line = NULL;
    size_t cap  = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) > 0) {
        if (len == 1 && line[0] == '\n') continue;
        char *operation = json_string(line, "operation");
        if (!operation)                                      emit_failure("no operation");
        else if (!strcmp(operation, "metadata"))             op_metadata();
        else if (!strcmp(operation, "ml-kem-keygen"))        op_ml_kem_keygen(line);
        else if (!strcmp(operation, "ml-kem-encapsulate"))   op_ml_kem_encapsulate(line);
        else if (!strcmp(operation, "ml-kem-decapsulate"))   op_ml_kem_decapsulate(line);
        else if (!strcmp(operation, "ml-kem-key-check"))     op_ml_kem_key_check(line);
        else if (!strcmp(operation, "ml-dsa-keygen"))        op_ml_dsa_keygen(line);
        else if (!strcmp(operation, "ml-dsa-sign"))          op_ml_dsa_sign(line);
        else if (!strcmp(operation, "ml-dsa-verify"))        op_ml_dsa_verify(line);
        else emit_impl_lacks("this harness answers ML-KEM and ML-DSA only");
        free(operation);
    }
    free(line);
    return 0;
}
