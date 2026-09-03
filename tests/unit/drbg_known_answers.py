"""Hash_DRBG and HMAC_DRBG answers taken from NIST's own live vector sets.

Session 765354 on the Demo server answered both mechanisms and returned
``"passed": true``; these are lifted from it. They live apart from any one
test module because a DRBG cannot be checked against a hand-written fixture --
any self-consistent implementation agrees with itself -- so both the offline
runner and the responder have to be held against these same bits.
"""

from __future__ import annotations

HASH_KNOWN: dict[str, object] = {
    "mode": "SHA2-256",
    "returnedBitsLen": 1024,
    "predResistance": True,
    "derFunc": False,
    "entropyInput": "E0B546C9868A1E5C3758CE1662C5CD18D7B2A8337BF8D2D839B3B7A411EE4098",
    "nonce": "0C4D8EE2223CB4660F288561967A8CA1",
    "persoString": "",
    "otherInput": [
        {
            "intendedUse": "generate",
            "additionalInput": "",
            "entropyInput": "4DE4047C8C9AAF2889BCB036D6040E9E23F74377008D7DF4968A179EC3727130",
        },
        {
            "intendedUse": "generate",
            "additionalInput": "",
            "entropyInput": "F019FE7CEE9BE9B58009DAF515ED1AC6CD9650D6137DBBDE3135656F409F6511",
        },
    ],
    "returnedBits": (
        "850827726CC8E1D557E48C89828CE55F1D53DC389934AA3D4055D308B22EC7E0"
        "B37492483E31566880443A98F21E0D3572CB10B290AFA3981D532EAE98FC27D8"
        "47715BE0B41632CD582DFD354490B04BEBD9B9C5EEC58F9DFF88A8A23274ADEF"
        "59B4F0FA0920609C47147FD3C22EC8D99E1CB277FE8F5CD13ECCC33D838963BD"
    ),
}

HMAC_KNOWN: dict[str, object] = {
    "mode": "SHA-1",
    "returnedBitsLen": 640,
    "predResistance": True,
    "derFunc": False,
    "entropyInput": "6A5E176A127CF09445C2C196F4C034BBC0290AF0",
    "nonce": "B95F8D33DF91AD86F3AE",
    "persoString": "0332C02AA5A656141C2CA2A47AB0389617D49B2A",
    "otherInput": [
        {
            "intendedUse": "generate",
            "additionalInput": "BF780F578AF7856AFD185A3D3FA98F23956382DB",
            "entropyInput": "026E29CE43F30F307BEAEFBA7918EB169FA72CB8",
        },
        {
            "intendedUse": "generate",
            "additionalInput": "633D2D0B3515AEB1BEEB6917AB11EDD6603BD942",
            "entropyInput": "877B12C836EF753CE49E7D169E9EC0573577A5EC",
        },
    ],
    "returnedBits": (
        "220497432CFAFBCC8832EDB41E9708158748C8A33A73FE4DBC3D017DFD950ABC"
        "25320EA5688C2CBBB38E2B01B32D525EA4127B0EC8201497F502C9F0E8355BCC"
        "9CE06B75237B962FFBEB87BD7E9676AE"
    ),
}

__all__ = ["HASH_KNOWN", "HMAC_KNOWN"]
