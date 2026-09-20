/*
 * acvp_harness.c -- a reference acvp-assay harness in C, backed by PKCS#11.
 *
 * The contract is deliberately small: read one JSON request per line on stdin,
 * write one JSON response per line on stdout, flush, repeat until stdin closes.
 * That is the whole protocol, which is why it can be implemented in a single
 * file with no dependencies beyond libdl and a PKCS#11 header.
 *
 * This one dispatches to a PKCS#11 token, because that is the case the runner
 * exists for: an HSM cannot be linked against, so it is driven over a pipe
 * instead. Swap the bodies of the op_* functions for your own SDK and the
 * protocol layer above them is unchanged.
 *
 * Build:
 *     cc -O2 -Wall -Wextra -o acvp_harness acvp_harness.c -ldl \
 *        -I/usr/include/p11-kit-1
 *
 * Run, with the PIN in a file only its owner can read:
 *     acvp-assay run prompt.json --provider-command \
 *         "./acvp_harness --module /usr/lib/softhsm/libsofthsm2.so \
 *          --pin-file /run/user/1000/acvp.pin"
 *
 * A PIN is never taken on the command line. argv is world readable through
 * /proc/PID/cmdline, and the runner keeps this harness alive for the whole
 * measurement, so an exposure there lasts the run rather than an instant.
 * --pin-fd N reads it from a descriptor the caller already opened, which keeps
 * it out of the filesystem as well; see docs/harness-protocol.md.
 *
 * Operations answered here: metadata, digest, digest-mct, mac,
 * block-transform (AES-ECB/CBC), encrypt and decrypt (AES-GCM). Everything
 * else is declined with {"error":"unsupported"}, which the runner reports as
 * UNSUPPORTED rather than as a failure -- capability is the implementation's
 * to declare, so declining is a first-class answer and not an error path.
 *
 * Two rules worth keeping if you adapt this:
 *
 *   - A rejected AES-GCM tag is {"error":"authentication failed"}, never a
 *     crash or a non-zero exit. Roughly a third of NIST's decrypt cases are
 *     deliberate forgeries where rejecting is the correct answer, and a
 *     harness that dies on them scores a conforming module as broken.
 *
 *   - Monte Carlo chains are answered whole. One round trip per inner
 *     iteration would take hours, and running the chain is what a real
 *     implementation does anyway.
 *
 * Public domain / CC0. Copy it into your tree and edit freely.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <p11-kit-1/p11-kit/pkcs11.h>

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

/* Decode hex into a fresh buffer. Returns NULL on malformed input; an empty
   string is valid and yields a zero-length buffer, which real vectors use for
   zero-length payloads and AAD. */
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

/* Copy a JSON string value into a fresh NUL-terminated buffer. The protocol
   sends hex and short identifiers, so only the escapes JSON requires are
   handled -- enough to be correct, not a general unescaper. */
static char *json_string(const char *json, const char *key)
{
    const char *v = find_value(json, key);
    if (!v || *v != '"') return NULL;
    v++;
    size_t cap = strlen(v) + 1;
    char *out = malloc(cap);
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

static int json_int(const char *json, const char *key, long *out)
{
    const char *v = find_value(json, key);
    if (!v) return 0;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v) return 0;
    *out = parsed;
    return 1;
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

static void emit_unsupported(void) { emit("{\"error\": \"unsupported\"}"); }

/* Report a PKCS#11 failure. The return value goes to stderr, which the runner
   passes through to your terminal but never puts in a report -- a failing
   module often quotes key material, and reports get shared as evidence. The
   JSON stays generic for the same reason. */
static void emit_rv(const char *where, CK_RV rv)
{
    fprintf(stderr, "acvp_harness: %s returned 0x%lx\n", where, (unsigned long)rv);

    /* Some failures are the token saying "I do not offer that", which is a
       capability statement rather than a fault: a key length outside its
       range, a mechanism it lacks, a key type it will not use that way. Those
       are reported unsupported, so the runner records a coverage gap instead
       of failing a module that is behaving correctly. Capability belongs to
       the implementation -- that is the whole reason this boundary exists. */
    switch (rv) {
    case CKR_KEY_SIZE_RANGE:
    case CKR_MECHANISM_INVALID:
    case CKR_MECHANISM_PARAM_INVALID:
    case CKR_KEY_TYPE_INCONSISTENT:
    case CKR_FUNCTION_NOT_SUPPORTED:
        emit_unsupported();
        return;
    default:
        emit("{\"error\": \"%s failed\"}", where);
    }
}
static void emit_auth_failed(void) { emit("{\"error\": \"authentication failed\"}"); }
static void emit_failure(const char *why) { emit("{\"error\": \"%s\"}", why); }

/* ---------------------------------------------------------------------- PIN */

/* A PIN never comes from argv. /proc/PID/cmdline is readable by every local
   user, and --provider-command keeps this harness alive for the whole run, so
   the exposure would last the measurement. It comes from a descriptor the
   caller opened, from a file whose mode keeps it private, or failing those from
   the environment, which is owner-only in /proc but is inherited by children. */

#define PIN_MAX 256

static char   pin_buffer[PIN_MAX];
static size_t pin_length;

/* Written through a volatile pointer so the store cannot be optimised away. */
static void zero_secret(void *data, size_t length)
{
    volatile unsigned char *byte = data;
    while (length--) *byte++ = 0;
}

/* Read a PIN from an open descriptor, to end of line or end of input. */
static int pin_read_fd(int fd, const char *what)
{
    size_t used = 0;
    for (;;) {
        if (used == sizeof pin_buffer) {
            fprintf(stderr, "acvp_harness: the PIN from %s is longer than %zu bytes\n",
                    what, sizeof pin_buffer);
            return 0;
        }
        ssize_t got = read(fd, pin_buffer + used, sizeof pin_buffer - used);
        if (got < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "acvp_harness: cannot read the PIN from %s: %s\n",
                    what, strerror(errno));
            return 0;
        }
        if (got == 0) break;
        used += (size_t)got;
        char *newline = memchr(pin_buffer, '\n', used);
        if (newline) { used = (size_t)(newline - pin_buffer); break; }
    }
    while (used && (pin_buffer[used - 1] == '\r' || pin_buffer[used - 1] == '\n')) used--;
    if (used == 0) {
        fprintf(stderr, "acvp_harness: the PIN from %s is empty\n", what);
        return 0;
    }
    pin_length = used;
    return 1;
}

/* A PIN file that anyone else can read is the same defect wearing a different
   hat, so refuse it and name the mode rather than logging in from it. */
static int pin_read_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "acvp_harness: cannot open %s: %s\n", path, strerror(errno));
        return 0;
    }
    struct stat status;
    if (fstat(fd, &status) != 0) {
        fprintf(stderr, "acvp_harness: cannot stat %s: %s\n", path, strerror(errno));
        close(fd);
        return 0;
    }
    if (status.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) {
        fprintf(stderr,
                "acvp_harness: %s is mode %04o, readable or writable beyond its owner; "
                "chmod 600 it\n",
                path, (unsigned)(status.st_mode & 07777));
        close(fd);
        return 0;
    }
    int ok = pin_read_fd(fd, path);
    close(fd);
    return ok;
}

/* Fill pin_buffer from whichever source the caller chose. Returns 0 only when a
   PIN was asked for and could not be read; no PIN at all is not an error, since
   a token may need no login. */
static int read_pin(const char *fd_text, const char *path)
{
    if (fd_text) {
        char *end = NULL;
        long fd = strtol(fd_text, &end, 10);
        if (*fd_text == '\0' || *end != '\0' || fd < 3 || fd > INT_MAX) {
            fprintf(stderr,
                    "acvp_harness: --pin-fd takes a descriptor of 3 or more; "
                    "0, 1 and 2 carry the protocol\n");
            return 0;
        }
        return pin_read_fd((int)fd, "--pin-fd");
    }
    if (path) return pin_read_file(path);

    const char *value = getenv("PKCS11_PIN");
    if (!value) return 1;
    size_t length = strlen(value);
    if (length == 0 || length > sizeof pin_buffer) {
        fprintf(stderr, "acvp_harness: PKCS11_PIN must be 1 to %zu bytes\n", sizeof pin_buffer);
        return 0;
    }
    memcpy(pin_buffer, value, length);
    pin_length = length;
    return 1;
}

/* ------------------------------------------------------------------ PKCS#11 */

static CK_FUNCTION_LIST_PTR p11;
static CK_SESSION_HANDLE    session;
static void                *module_handle;
static const char          *module_path = "(none)";

static int p11_start(const char *path, CK_SLOT_ID wanted, int have_slot)
{
    module_handle = dlopen(path, RTLD_NOW);
    if (!module_handle) {
        fprintf(stderr, "acvp_harness: dlopen %s: %s\n", path, dlerror());
        return 0;
    }
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR) = dlsym(module_handle, "C_GetFunctionList");
    if (!get_list) {
        fprintf(stderr, "acvp_harness: %s exports no C_GetFunctionList\n", path);
        return 0;
    }
    if (get_list(&p11) != CKR_OK || !p11) {
        fprintf(stderr, "acvp_harness: C_GetFunctionList failed\n");
        return 0;
    }
    CK_RV rv = p11->C_Initialize(NULL);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stderr, "acvp_harness: C_Initialize failed (0x%lx)\n", (unsigned long)rv);
        return 0;
    }

    CK_SLOT_ID slot = wanted;
    if (!have_slot) {
        CK_ULONG count = 0;
        if (p11->C_GetSlotList(CK_TRUE, NULL, &count) != CKR_OK || count == 0) {
            fprintf(stderr, "acvp_harness: no slot with a token present\n");
            return 0;
        }
        CK_SLOT_ID *slots = calloc(count, sizeof *slots);
        if (!slots || p11->C_GetSlotList(CK_TRUE, slots, &count) != CKR_OK) {
            free(slots);
            fprintf(stderr, "acvp_harness: C_GetSlotList failed\n");
            return 0;
        }
        slot = slots[0];
        free(slots);
    }

    rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "acvp_harness: C_OpenSession failed (0x%lx)\n", (unsigned long)rv);
        return 0;
    }
    if (pin_length) {
        rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin_buffer, (CK_ULONG)pin_length);
        /* Nothing after the login needs the PIN, so it does not sit in memory
           for the length of the run. This runs on the failure path too. */
        zero_secret(pin_buffer, sizeof pin_buffer);
        pin_length = 0;
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            fprintf(stderr, "acvp_harness: C_Login failed (0x%lx)\n", (unsigned long)rv);
            return 0;
        }
    }
    module_path = path;
    return 1;
}

/* A session-only secret key built from raw bytes. Vectors supply keys, so the
   harness imports rather than generates; CKA_TOKEN false keeps nothing behind
   on the token after the run. */
static int import_key(const unsigned char *key, size_t key_len,
                      CK_KEY_TYPE type, CK_ATTRIBUTE_TYPE usage,
                      CK_OBJECT_HANDLE *out)
{
    CK_OBJECT_CLASS klass = CKO_SECRET_KEY;
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS,    &klass, sizeof klass },
        { CKA_KEY_TYPE, &type,  sizeof type  },
        { CKA_TOKEN,    &no,    sizeof no    },
        { CKA_VALUE,    (void *)key, (CK_ULONG)key_len },
        { usage,        &yes,   sizeof yes   },
        { CKA_DECRYPT,  &yes,   sizeof yes   },
    };
    CK_ULONG n = (usage == CKA_ENCRYPT) ? 6 : 5;
    return p11->C_CreateObject(session, attrs, n, out) == CKR_OK;
}

static void discard_key(CK_OBJECT_HANDLE key)
{
    if (key) p11->C_DestroyObject(session, key);
}

/* --------------------------------------------------------- mechanism tables */

static CK_MECHANISM_TYPE digest_mechanism(const char *name)
{
    if (!strcmp(name, "SHA-1"))     return CKM_SHA_1;
    if (!strcmp(name, "SHA2-224"))  return CKM_SHA224;
    if (!strcmp(name, "SHA2-256"))  return CKM_SHA256;
    if (!strcmp(name, "SHA2-384"))  return CKM_SHA384;
    if (!strcmp(name, "SHA2-512"))  return CKM_SHA512;
    return 0;
}

static CK_MECHANISM_TYPE hmac_mechanism(const char *name)
{
    if (!strcmp(name, "HMAC-SHA-1"))    return CKM_SHA_1_HMAC;
    if (!strcmp(name, "HMAC-SHA2-224")) return CKM_SHA224_HMAC;
    if (!strcmp(name, "HMAC-SHA2-256")) return CKM_SHA256_HMAC;
    if (!strcmp(name, "HMAC-SHA2-384")) return CKM_SHA384_HMAC;
    if (!strcmp(name, "HMAC-SHA2-512")) return CKM_SHA512_HMAC;
    return 0;
}

static size_t digest_length(CK_MECHANISM_TYPE m)
{
    switch (m) {
    case CKM_SHA_1:  return 20;
    case CKM_SHA224: return 28;
    case CKM_SHA256: return 32;
    case CKM_SHA384: return 48;
    case CKM_SHA512: return 64;
    default:         return 0;
    }
}

static int do_digest(CK_MECHANISM_TYPE mech, const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t *out_len)
{
    CK_MECHANISM m = { mech, NULL, 0 };
    if (p11->C_DigestInit(session, &m) != CKR_OK) return 0;
    CK_ULONG n = (CK_ULONG)*out_len;
    /* An empty message is legitimate; pass a non-NULL pointer regardless,
       because some modules reject NULL even with a zero length. */
    unsigned char nothing = 0;
    if (p11->C_Digest(session, (CK_BYTE_PTR)(in_len ? in : &nothing),
                      (CK_ULONG)in_len, out, &n) != CKR_OK)
        return 0;
    *out_len = n;
    return 1;
}

/* ------------------------------------------------------------------ handlers */

static void op_metadata(void)
{
    CK_INFO info;
    char library[33] = "unknown", version[32] = "unknown";
    if (p11->C_GetInfo(&info) == CKR_OK) {
        size_t n = sizeof info.manufacturerID;
        memcpy(library, info.manufacturerID, n);
        library[n] = '\0';
        for (int i = (int)n - 1; i >= 0 && library[i] == ' '; i--) library[i] = '\0';
        snprintf(version, sizeof version, "%u.%u",
                 info.libraryVersion.major, info.libraryVersion.minor);
    }
    /* C_GetInfo and C_GetTokenInfo name the module and give two-part versions,
     * which two builds of one release share. Neither structure carries a build
     * identifier, so say so rather than passing a version off as one. */
    emit("{\"name\": \"pkcs11-harness\", \"libraryName\": \"%s\", "
         "\"libraryVersion\": \"%s\", \"backendName\": \"PKCS#11\", "
         "\"backendVersion\": \"%s\", \"buildId\": null, "
         "\"buildIdAbsentReason\": \"not_exposed\"}", library, version, module_path);
}

static void op_digest(const char *line)
{
    char *algorithm = json_string(line, "algorithm");
    char *message   = json_string(line, "message");
    if (!algorithm || !message) { emit_failure("missing algorithm or message"); goto done; }

    CK_MECHANISM_TYPE mech = digest_mechanism(algorithm);
    if (!mech) { emit_unsupported(); goto done; }

    size_t in_len = 0;
    unsigned char *in = hex_decode(message, &in_len);
    if (!in) { emit_failure("invalid hex in message"); goto done; }

    unsigned char md[64];
    size_t md_len = sizeof md;
    if (!do_digest(mech, in, in_len, md, &md_len)) {
        free(in);
        emit_failure("digest failed");
        goto done;
    }
    free(in);

    Buf out = {0};
    buf_puts(&out, "{\"md\": \"");
    buf_add_hex(&out, md, md_len);
    buf_puts(&out, "\"}");
    emit_buf(&out);
    buf_free(&out);
done:
    free(algorithm);
    free(message);
}

/* The SHA-2 Monte Carlo chain, delegated whole. One round trip per inner
   iteration would be 100,000 exchanges per case.

   Two details the specification makes easy to get wrong, and both are here:

     - The seed is not necessarily digest-sized. In the alternate variant it is
       whatever width the vector supplies, and every message is truncated or
       zero-padded to the width of the *original* seed -- captured once, before
       the loop, not recomputed as the chain's values shrink to digest length.

     - Each outer iteration restarts a, b and c from the current seed, and the
       seed becomes the digest that iteration produced.

   SHA-3 chains a single digest per iteration rather than three concatenated,
   so it is a different chain and is declined here rather than answered with
   this one. */
static void op_digest_mct(const char *line)
{
    char *algorithm = json_string(line, "algorithm");
    char *seed_hex  = json_string(line, "seed");
    unsigned char *seed = NULL, *a = NULL, *b = NULL, *c = NULL, *message = NULL;
    if (!algorithm || !seed_hex) { emit_failure("missing algorithm or seed"); goto done; }

    CK_MECHANISM_TYPE mech = digest_mechanism(algorithm);
    size_t dlen = digest_length(mech);
    if (!mech || !dlen) { emit_unsupported(); goto done; }

    int alternate = json_bool(line, "alternate");
    size_t width = 0;
    seed = hex_decode(seed_hex, &width);
    if (!seed || width == 0) { emit_failure("invalid or empty seed"); goto done; }

    /* a, b and c start seed-width and shrink to digest-width; the message is
       their concatenation, optionally resized to the original width. */
    size_t room = (width > dlen ? width : dlen);
    a = malloc(room); b = malloc(room); c = malloc(room);
    message = malloc(3 * room + width + 1);
    if (!a || !b || !c || !message) { emit_failure("out of memory"); goto done; }

    size_t seed_len = width;
    Buf out = {0};
    buf_puts(&out, "{\"md\": [");
    for (int outer = 0; outer < 100; outer++) {
        size_t alen = seed_len, blen = seed_len, clen = seed_len;
        memcpy(a, seed, seed_len);
        memcpy(b, seed, seed_len);
        memcpy(c, seed, seed_len);

        for (int inner = 0; inner < 1000; inner++) {
            size_t n = 0;
            memcpy(message + n, a, alen); n += alen;
            memcpy(message + n, b, blen); n += blen;
            memcpy(message + n, c, clen); n += clen;
            if (alternate) {
                if (n < width) memset(message + n, 0, width - n);
                n = width;
            }
            unsigned char md[64];
            size_t md_len = sizeof md;
            if (!do_digest(mech, message, n, md, &md_len)) {
                buf_free(&out);
                emit_failure("digest failed");
                goto done;
            }
            memcpy(a, b, blen); alen = blen;
            memcpy(b, c, clen); blen = clen;
            memcpy(c, md, md_len); clen = md_len;
        }
        if (outer) buf_puts(&out, ", ");
        buf_puts(&out, "\"");
        buf_add_hex(&out, c, clen);
        buf_puts(&out, "\"");
        memcpy(seed, c, clen);
        seed_len = clen;
    }
    buf_puts(&out, "]}");
    emit_buf(&out);
    buf_free(&out);
done:
    free(algorithm); free(seed_hex); free(seed);
    free(a); free(b); free(c); free(message);
}

static void op_mac(const char *line)
{
    char *algorithm = json_string(line, "algorithm");
    char *key_hex   = json_string(line, "key");
    char *msg_hex   = json_string(line, "message");
    long  mac_bits  = 0;
    unsigned char *key = NULL, *msg = NULL;
    CK_OBJECT_HANDLE handle = 0;

    if (!algorithm || !key_hex || !msg_hex || !json_int(line, "macLen", &mac_bits)) {
        emit_failure("missing algorithm, key, message or macLen");
        goto done;
    }
    CK_MECHANISM_TYPE mech = hmac_mechanism(algorithm);
    if (!mech) { emit_unsupported(); goto done; }

    size_t key_len = 0, msg_len = 0;
    key = hex_decode(key_hex, &key_len);
    msg = hex_decode(msg_hex, &msg_len);
    if (!key || !msg) { emit_failure("invalid hex"); goto done; }

    if (!import_key(key, key_len, CKK_GENERIC_SECRET, CKA_SIGN, &handle)) {
        emit_failure("could not import the key");
        goto done;
    }

    CK_MECHANISM m = { mech, NULL, 0 };
    CK_RV rv = p11->C_SignInit(session, &m, handle);
    if (rv != CKR_OK) { emit_rv("C_SignInit", rv); goto done; }
    unsigned char mac[64];
    CK_ULONG mac_len = sizeof mac;
    unsigned char nothing = 0;
    rv = p11->C_Sign(session, (CK_BYTE_PTR)(msg_len ? msg : &nothing),
                     (CK_ULONG)msg_len, mac, &mac_len);
    if (rv != CKR_OK) { emit_rv("C_Sign", rv); goto done; }

    /* ACVP truncates the MAC to macLen bits; the group decides, not the
       mechanism. Truncating here rather than returning the full tag is what
       the runner compares against. */
    size_t want = (size_t)mac_bits / 8;
    if (want > mac_len) { emit_failure("macLen exceeds the mechanism output"); goto done; }

    Buf out = {0};
    buf_puts(&out, "{\"mac\": \"");
    buf_add_hex(&out, mac, want);
    buf_puts(&out, "\"}");
    emit_buf(&out);
    buf_free(&out);
done:
    discard_key(handle);
    free(algorithm); free(key_hex); free(msg_hex); free(key); free(msg);
}

static void op_block_transform(const char *line)
{
    char *algorithm = json_string(line, "algorithm");
    char *direction = json_string(line, "direction");
    char *key_hex   = json_string(line, "key");
    char *iv_hex    = json_string(line, "iv");
    char *data_hex  = json_string(line, "data");
    unsigned char *key = NULL, *iv = NULL, *data = NULL, *out_bytes = NULL;
    CK_OBJECT_HANDLE handle = 0;

    if (!algorithm || !direction || !key_hex || !data_hex) {
        emit_failure("missing algorithm, direction, key or data");
        goto done;
    }

    CK_MECHANISM_TYPE mech;
    if (!strcmp(algorithm, "ACVP-AES-ECB"))      mech = CKM_AES_ECB;
    else if (!strcmp(algorithm, "ACVP-AES-CBC")) mech = CKM_AES_CBC;
    else { emit_unsupported(); goto done; }

    int encrypt = !strcmp(direction, "encrypt");
    size_t key_len = 0, iv_len = 0, data_len = 0;
    key  = hex_decode(key_hex, &key_len);
    data = hex_decode(data_hex, &data_len);
    if (iv_hex) iv = hex_decode(iv_hex, &iv_len);
    if (!key || !data) { emit_failure("invalid hex"); goto done; }

    if (!import_key(key, key_len, CKK_AES, encrypt ? CKA_ENCRYPT : CKA_DECRYPT, &handle)) {
        emit_failure("could not import the key");
        goto done;
    }

    CK_MECHANISM m = { mech, mech == CKM_AES_CBC ? iv : NULL,
                       mech == CKM_AES_CBC ? (CK_ULONG)iv_len : 0 };
    CK_RV rv = encrypt ? p11->C_EncryptInit(session, &m, handle)
                       : p11->C_DecryptInit(session, &m, handle);
    if (rv != CKR_OK) { emit_rv("cipher init", rv); goto done; }

    CK_ULONG out_len = (CK_ULONG)data_len + 16;
    out_bytes = malloc(out_len);
    if (!out_bytes) { emit_failure("out of memory"); goto done; }
    rv = encrypt ? p11->C_Encrypt(session, data, (CK_ULONG)data_len, out_bytes, &out_len)
                 : p11->C_Decrypt(session, data, (CK_ULONG)data_len, out_bytes, &out_len);
    if (rv != CKR_OK) { emit_rv("cipher", rv); goto done; }

    Buf out = {0};
    buf_puts(&out, "{\"out\": \"");
    buf_add_hex(&out, out_bytes, out_len);
    buf_puts(&out, "\"}");
    emit_buf(&out);
    buf_free(&out);
done:
    discard_key(handle);
    free(algorithm); free(direction); free(key_hex); free(iv_hex); free(data_hex);
    free(key); free(iv); free(data); free(out_bytes);
}

static void op_gcm(const char *line, int encrypt)
{
    char *key_hex = json_string(line, "key");
    char *iv_hex  = json_string(line, "iv");
    char *aad_hex = json_string(line, "aad");
    char *pt_hex  = json_string(line, encrypt ? "pt" : "ct");
    char *tag_hex = encrypt ? NULL : json_string(line, "tag");
    long  tag_bits = 128;
    unsigned char *key = NULL, *iv = NULL, *aad = NULL, *payload = NULL;
    unsigned char *tag = NULL, *joined = NULL, *out_bytes = NULL;
    CK_OBJECT_HANDLE handle = 0;

    if (!key_hex || !iv_hex || !pt_hex) { emit_failure("missing key, iv or payload"); goto done; }
    if (encrypt) json_int(line, "tagLen", &tag_bits);

    size_t key_len = 0, iv_len = 0, aad_len = 0, payload_len = 0, tag_len = 0;
    key     = hex_decode(key_hex, &key_len);
    iv      = hex_decode(iv_hex, &iv_len);
    payload = hex_decode(pt_hex, &payload_len);
    aad     = aad_hex ? hex_decode(aad_hex, &aad_len) : calloc(1, 1);
    if (tag_hex) { tag = hex_decode(tag_hex, &tag_len); tag_bits = (long)tag_len * 8; }
    if (!key || !iv || !payload || !aad) { emit_failure("invalid hex"); goto done; }

    if (!import_key(key, key_len, CKK_AES, encrypt ? CKA_ENCRYPT : CKA_DECRYPT, &handle)) {
        emit_failure("could not import the key");
        goto done;
    }

    CK_GCM_PARAMS params;
    params.pIv      = iv;
    params.ulIvLen  = (CK_ULONG)iv_len;
    params.ulIvBits = (CK_ULONG)iv_len * 8;
    params.pAAD     = aad;
    params.ulAADLen = (CK_ULONG)aad_len;
    params.ulTagBits = (CK_ULONG)tag_bits;
    CK_MECHANISM m = { CKM_AES_GCM, &params, sizeof params };

    if (encrypt) {
        CK_RV rv = p11->C_EncryptInit(session, &m, handle);
        if (rv != CKR_OK) { emit_rv("C_EncryptInit", rv); goto done; }
        /* PKCS#11 returns ciphertext and tag concatenated. */
        CK_ULONG out_len = (CK_ULONG)(payload_len + tag_bits / 8 + 16);
        out_bytes = malloc(out_len);
        if (!out_bytes) { emit_failure("out of memory"); goto done; }
        rv = p11->C_Encrypt(session, payload, (CK_ULONG)payload_len, out_bytes, &out_len);
        if (rv != CKR_OK) { emit_rv("C_Encrypt", rv); goto done; }
        size_t tlen = (size_t)tag_bits / 8;
        if (out_len < tlen) { emit_failure("short GCM output"); goto done; }
        size_t clen = out_len - tlen;

        Buf out = {0};
        buf_puts(&out, "{\"ct\": \"");
        buf_add_hex(&out, out_bytes, clen);
        buf_puts(&out, "\", \"tag\": \"");
        buf_add_hex(&out, out_bytes + clen, tlen);
        buf_puts(&out, "\"}");
        emit_buf(&out);
        buf_free(&out);
    } else {
        if (!tag) { emit_failure("missing tag"); goto done; }
        CK_RV rv = p11->C_DecryptInit(session, &m, handle);
        if (rv != CKR_OK) { emit_rv("C_DecryptInit", rv); goto done; }
        joined = malloc(payload_len + tag_len + 1);
        if (!joined) { emit_failure("out of memory"); goto done; }
        memcpy(joined, payload, payload_len);
        memcpy(joined + payload_len, tag, tag_len);

        CK_ULONG out_len = (CK_ULONG)payload_len + 16;
        out_bytes = malloc(out_len + 1);
        if (!out_bytes) { emit_failure("out of memory"); goto done; }
        rv = p11->C_Decrypt(session, joined, (CK_ULONG)(payload_len + tag_len),
                            out_bytes, &out_len);
        if (rv == CKR_ENCRYPTED_DATA_INVALID || rv == CKR_DATA_INVALID ||
            rv == CKR_SIGNATURE_INVALID || rv == CKR_GENERAL_ERROR) {
            /* A forged tag is a correct answer, not a fault. Roughly a third
               of NIST's decrypt cases are deliberate failures. */
            emit_auth_failed();
            goto done;
        }
        if (rv != CKR_OK) { emit_rv("C_Decrypt", rv); goto done; }

        Buf out = {0};
        buf_puts(&out, "{\"pt\": \"");
        buf_add_hex(&out, out_bytes, out_len);
        buf_puts(&out, "\"}");
        emit_buf(&out);
        buf_free(&out);
    }
done:
    discard_key(handle);
    free(key_hex); free(iv_hex); free(aad_hex); free(pt_hex); free(tag_hex);
    free(key); free(iv); free(aad); free(payload); free(tag); free(joined); free(out_bytes);
}

/* ---------------------------------------------------------------------- main */

static void usage(void)
{
    fprintf(stderr,
        "usage: acvp_harness --module PATH [--pin-fd N | --pin-file PATH] [--slot ID]\n"
        "\n"
        "Reads one JSON request per line on stdin and writes one response per\n"
        "line on stdout. Intended to be run by acvp-assay --provider-command.\n"
        "\n"
        "A PIN is never taken on the command line: argv is world readable through\n"
        "/proc/PID/cmdline. Pass --pin-fd N to read it from a descriptor the\n"
        "caller already opened, --pin-file PATH to read it from a file that is not\n"
        "readable beyond its owner, or set PKCS11_PIN, which is owner-only in\n"
        "/proc but is inherited by every child. --module may also come from\n"
        "PKCS11_MODULE, and --slot picks a slot; without it the first slot with a\n"
        "token is used.\n");
}

int main(int argc, char **argv)
{
    const char *module      = getenv("PKCS11_MODULE");
    const char *pin_fd_text = NULL;
    const char *pin_file    = NULL;
    CK_SLOT_ID  slot        = 0;
    int have_slot = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--module") && i + 1 < argc)        module = argv[++i];
        else if (!strcmp(argv[i], "--pin-fd") && i + 1 < argc)   pin_fd_text = argv[++i];
        else if (!strcmp(argv[i], "--pin-file") && i + 1 < argc) pin_file = argv[++i];
        else if (!strcmp(argv[i], "--slot") && i + 1 < argc) {
            slot = (CK_SLOT_ID)strtoul(argv[++i], NULL, 0);
            have_slot = 1;
        } else { usage(); return 2; }
    }
    if (!module) { usage(); return 2; }
    if (pin_fd_text && pin_file) {
        fprintf(stderr, "acvp_harness: pass --pin-fd or --pin-file, not both\n");
        return 2;
    }
    if (!read_pin(pin_fd_text, pin_file)) {
        zero_secret(pin_buffer, sizeof pin_buffer);
        return 2;
    }
    if (!p11_start(module, slot, have_slot)) {
        zero_secret(pin_buffer, sizeof pin_buffer);
        return 1;
    }
    zero_secret(pin_buffer, sizeof pin_buffer);

    char  *line = NULL;
    size_t cap  = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) > 0) {
        if (len == 1 && line[0] == '\n') continue;
        char *operation = json_string(line, "operation");
        if (!operation)                                emit_failure("no operation");
        else if (!strcmp(operation, "metadata"))       op_metadata();
        else if (!strcmp(operation, "digest"))         op_digest(line);
        else if (!strcmp(operation, "digest-mct"))     op_digest_mct(line);
        else if (!strcmp(operation, "mac"))            op_mac(line);
        else if (!strcmp(operation, "block-transform")) op_block_transform(line);
        else if (!strcmp(operation, "encrypt"))        op_gcm(line, 1);
        else if (!strcmp(operation, "decrypt"))        op_gcm(line, 0);
        else                                           emit_unsupported();
        free(operation);
    }
    free(line);

    if (p11) { p11->C_CloseSession(session); p11->C_Finalize(NULL); }
    if (module_handle) dlclose(module_handle);
    return 0;
}
