#!/usr/bin/env python3
"""
GOOSE frame generator — IEC 61850-8-1 + IEC 62351-6 security wrapper.

Three build modes:
  plain    : bare L2 GOOSE frame (EtherType 0x88B8), no security. Dissects fully
             with Wireshark's standard `goose` dissector.
  l2sec    : L2 GOOSE frame + signature appended as a trailer AFTER the APDU.
             The 8-byte header `Length` covers only header+APDU, so Wireshark
             dissects the goosePdu cleanly and the signature shows as trailing
             bytes. This is the "firma va detrás del APDU" shape.
  session  : full IEC 62351-6 Session PDU (SPDU 0xA1 ... + HMAC/signature trailer),
             the structure Wireshark parses in dissect_rgoose. Emitted with exact
             field offsets; live dissection needs a CLNP/CLTP outer wrapper (TODO).

Signatures:
  ecdsa-p256 / ecdsa-bp256 : REAL signatures via `cryptography` (deterministic key).
  mldsa44 / mldsa65 / falcon512 / slhdsa-128s / slhdsa-128f :
      PLACEHOLDER bytes of the canonical signature size (clearly labeled). Wire
      out the real signer once liboqs-python is installed (see repo/). Per CLAUDE.md
      these are transport/size probes, NOT measured crypto.

This is a size-accounting + wire-format probe. It is NOT a deployable scheme:
a deployable composite would carry composite-OID domain-separation binding
(draft-ietf-lamps-pq-composite-sigs). See CLAUDE.md §2.
"""

import argparse
import struct

# --- signature schemes. Real signatures now: ECDSA via `cryptography`, PQC via
# liboqs-python (the homogeneous-stack liboqs 0.15.0). `oqs_name` is the liboqs
# algorithm id; None -> ECDSA path. `sig` is the canonical/nominal size used only
# as a fallback when the library is unavailable. -------------------------------
SCHEMES = {
    "ecdsa-p256":  {"sig": 72,    "pub": 65,   "nist": "L1", "oqs_name": None},
    "ecdsa-bp256": {"sig": 71,    "pub": 65,   "nist": "L1", "oqs_name": None},
    "mldsa44":     {"sig": 2420,  "pub": 1312, "nist": "L2", "oqs_name": "ML-DSA-44"},
    "mldsa65":     {"sig": 3309,  "pub": 1952, "nist": "L3", "oqs_name": "ML-DSA-65"},
    "falcon512":   {"sig": 666,   "pub": 897,  "nist": "L1", "oqs_name": "Falcon-512"},
    "slhdsa-128s": {"sig": 7856,  "pub": 32,   "nist": "L1", "oqs_name": "SPHINCS+-SHA2-128s-simple"},
    "slhdsa-128f": {"sig": 17088, "pub": 32,   "nist": "L1", "oqs_name": "SPHINCS+-SHA2-128f-simple"},
}

ETHERTYPE_GOOSE = 0x88B8
GOOSE_MCAST_DST = bytes.fromhex("010ccd010001")  # GOOSE multicast range 01:0C:CD:01:xx:xx
DEFAULT_SRC     = bytes.fromhex("001122334455")
MAX_ETH_PAYLOAD = 1500  # standard Ethernet payload ceiling; GOOSE does NOT fragment


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def tlv(tag, val):
    return bytes([tag]) + ber_len(len(val)) + val


def _ctx_int(tag, n):
    if n == 0:
        v = b"\x00"
    else:
        v = []
        m = n
        while m:
            v.insert(0, m & 0xFF)
            m >>= 8
        if v[0] & 0x80:
            v.insert(0, 0)  # keep it a positive INTEGER
        v = bytes(v)
    return tlv(0x80 | tag, v)


def _ctx_str(tag, s):
    return tlv(0x80 | tag, s.encode())


def _ctx_bool(tag, b):
    return tlv(0x80 | tag, b"\xff" if b else b"\x00")


# --- GOOSE APDU (goosePdu, APPLICATION 1 = 0x61) ---------------------------
def build_goose_pdu(st_num=7, sq_num=0, gocb_ref="AA1J1Q01/LLN0$GO$gcb01",
                    dat_set="AA1J1Q01/LLN0$DS$ds01", go_id="AA1J1Q01/LLN0.gcb01",
                    tal_ms=2000, conf_rev=1):
    # UtcTime [4]: 4B seconds + 3B fraction + 1B quality
    utctime = tlv(0x84, struct.pack(">I", 0x66600000) + b"\x00\x00\x00" + b"\x0a")
    # allData [11]: one boolean=TRUE (Data CHOICE boolean = [3])
    all_data = tlv(0xAB, tlv(0x83, b"\xff"))

    pdu  = _ctx_str(0, gocb_ref)        # gocbRef
    pdu += _ctx_int(1, tal_ms)          # timeAllowedToLive
    pdu += _ctx_str(2, dat_set)         # datSet
    pdu += _ctx_str(3, go_id)           # goID
    pdu += utctime                      # t
    pdu += _ctx_int(5, st_num)          # stNum
    pdu += _ctx_int(6, sq_num)          # sqNum
    pdu += _ctx_bool(7, False)          # simulation
    pdu += _ctx_int(8, conf_rev)        # confRev
    pdu += _ctx_bool(9, False)          # ndsCom
    pdu += _ctx_int(10, 1)              # numDatSetEntries
    pdu += all_data                     # allData
    return tlv(0x61, pdu)               # goosePdu [APPLICATION 1]


def sign(scheme, msg):
    """Return (signature_bytes, is_real). Real signatures via cryptography (ECDSA)
    or liboqs-python (PQC). Falls back to a labeled placeholder only if liboqs is
    unavailable, so size probes still work without the homogeneous stack."""
    meta = SCHEMES[scheme]
    if meta["oqs_name"] is None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        curve = ec.SECP256R1() if scheme == "ecdsa-p256" else ec.BrainpoolP256R1()
        # fixed scalar -> reproducible key (NOT for production; bench determinism)
        priv = ec.derive_private_key(0x1234_5678_9abc_def0_1122_3344_5566_7788, curve)
        return priv.sign(msg, ec.ECDSA(hashes.SHA256())), True  # DER, ~70-72 B
    try:
        import oqs
        with oqs.Signature(meta["oqs_name"]) as s:
            s.generate_keypair()
            return s.sign(msg), True
    except Exception:
        # liboqs not available: labeled placeholder of canonical size
        return bytes([0xA5]) * meta["sig"], False


# --- mode: plain L2 GOOSE --------------------------------------------------
def build_plain(pdu, appid=0x0001):
    length = 8 + len(pdu)                       # APPID+Length+Rsv1+Rsv2 = 8
    apdu = struct.pack(">H", appid) + struct.pack(">H", length) + b"\x00\x00" + b"\x00\x00" + pdu
    return apdu, length


# --- mode: L2 GOOSE + signature trailer (IEC 62351-6 extension, probe) ------
def build_l2sec(pdu, scheme, appid=0x0001):
    """
    Length field covers ONLY header+APDU (so the standard dissector parses the
    goosePdu and stops). Reserved2 carries the actual security-extension length
    as a probe-level signal. The signature is appended as a trailer after the APDU.
    Signed region = APPID+Length+Reserved1+APDU (i.e. everything except Reserved2,
    which is the extension-length field, and the trailer itself). This keeps the
    signature stable while letting Reserved2 hold the real (variable) trailer length.
    """
    length = 8 + len(pdu)
    rsv1 = b"\x00\x00"
    head6 = struct.pack(">H", appid) + struct.pack(">H", length) + rsv1
    sig, is_real = sign(scheme, head6 + pdu)      # sign head(6B)+APDU
    rsv2 = struct.pack(">H", len(sig) & 0xFFFF)   # probe: real extension length
    apdu = head6 + rsv2 + pdu + sig
    return apdu, length, sig, is_real


# --- mode: full IEC 62351-6 Session PDU + HMAC/signature trailer ------------
def build_session(pdu, scheme, appid=0x0001, spdu_num=1, key_id=0x0000_0001):
    """
    Session PDU layout (matches Wireshark dissect_rgoose field offsets):
      SPDU ID            1   0xA1 (GOOSE)         OSI_SPDU_GOOSE
      Session hdr len    1
      Content id         1   0x80
      Length             1
      SPDU length        4
      SPDU number        4   <- strong anti-replay counter
      Version            2
      -- Security information --
      Time of current key 4
      Time of next key    2
      Key ID              4
      Init vector len     1   (0 here: signing, not encrypting)
      [Init vector]       iv
      -- Session user information --
      Payload length      4
      Payload:
        APDU tag          1   0x81 (OSI_PDU_GOOSE)
        Simulation flag   1
        APPID             2
        APDU length       2
        goosePdu          ...
      [Padding]           0xAF + len + bytes      (optional, omitted)
      Signature/HMAC      remaining bytes  <- trailer
    Signed message = whole session PDU up to (not including) the trailer.
    """
    payload_body = (
        b"\x81"                                  # APDU tag = GOOSE
        + b"\x00"                                # simulation flag
        + struct.pack(">H", appid)               # APPID
        + struct.pack(">H", len(pdu))            # APDU length
        + pdu                                    # goosePdu
    )
    payload = struct.pack(">I", len(payload_body)) + payload_body

    sec_info = (
        struct.pack(">I", 0x6660_0000)           # time of current key
        + struct.pack(">H", 0x0000)              # time of next key
        + struct.pack(">I", key_id)              # key id
        + b"\x00"                                # IV length = 0
    )

    spdu_body_after_len = (
        b"\x80"                                  # content id
        + b"\x18"                                # length (cosmetic)
        + struct.pack(">I", 0)                   # SPDU length (patched below)
        + struct.pack(">I", spdu_num)            # SPDU number
        + struct.pack(">H", 0x0001)              # version
        + sec_info
        + payload
    )
    # session header length byte = content-id..end of security info
    sess_hdr_len = 2 + 4 + 4 + 2 + len(sec_info)

    session_pdu = b"\xa1" + bytes([sess_hdr_len & 0xFF]) + spdu_body_after_len
    # patch SPDU length: field sits at offset 4..8; value = bytes after it
    spdu_length = len(session_pdu) - 8
    session_pdu = session_pdu[:4] + struct.pack(">I", spdu_length) + session_pdu[8:]

    sig, is_real = sign(scheme, session_pdu)
    return session_pdu + sig, sig, is_real


def wrap_eth(apdu, dst=GOOSE_MCAST_DST, src=DEFAULT_SRC, ethertype=ETHERTYPE_GOOSE):
    eth = dst + src + struct.pack(">H", ethertype) + apdu
    if len(eth) < 60:
        eth += b"\x00" * (60 - len(eth))         # pad to Ethernet min (no FCS)
    return eth


def write_pcap(path, eth):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # EN10MB
        f.write(struct.pack("<IIII", 0x6660_0000, 0, len(eth), len(eth)))
        f.write(eth)


def report(mode, scheme, eth, sig=None, is_real=None):
    on_air = len(eth)                            # incl. 14B Eth header, no FCS/VLAN
    payload = on_air - 14
    fits = payload <= MAX_ETH_PAYLOAD
    print(f"  mode={mode:8s} scheme={scheme or '-':12s}")
    if sig is not None:
        kind = "REAL" if is_real else "PLACEHOLDER (size only)"
        print(f"    signature      : {len(sig):6d} B   [{kind}]")
    print(f"    frame on-air   : {on_air:6d} B   (Eth14 + {payload} B payload, no FCS/VLAN)")
    print(f"    single-frame   : {'PASS' if fits else 'FAIL'}  "
          f"(payload {payload} {'<=' if fits else '>'} {MAX_ETH_PAYLOAD} B ceiling)")


def main():
    ap = argparse.ArgumentParser(description="GOOSE / IEC 62351-6 frame generator")
    ap.add_argument("--mode", choices=["plain", "l2sec", "session"], default="plain")
    ap.add_argument("--scheme", choices=list(SCHEMES), default="ecdsa-p256")
    ap.add_argument("--out", default="/tmp/goose.pcap")
    ap.add_argument("--all", action="store_true",
                    help="emit one pcap per scheme for l2sec mode + size table")
    args = ap.parse_args()

    pdu = build_goose_pdu()

    if args.all:
        print("IEC 62351-6 L2-secured GOOSE — single-frame size accounting")
        print("=" * 64)
        for sch in SCHEMES:
            apdu, _, sig, is_real = build_l2sec(pdu, sch)
            eth = wrap_eth(apdu)
            write_pcap(f"/tmp/goose_l2sec_{sch}.pcap", eth)
            report("l2sec", sch, eth, sig, is_real)
        return

    if args.mode == "plain":
        apdu, _ = build_plain(pdu)
        eth = wrap_eth(apdu)
        write_pcap(args.out, eth)
        report("plain", None, eth)
    elif args.mode == "l2sec":
        apdu, _, sig, is_real = build_l2sec(pdu, args.scheme)
        eth = wrap_eth(apdu)
        write_pcap(args.out, eth)
        report("l2sec", args.scheme, eth, sig, is_real)
    else:  # session
        apdu, sig, is_real = build_session(pdu, args.scheme)
        eth = wrap_eth(apdu)
        write_pcap(args.out, eth)
        report("session", args.scheme, eth, sig, is_real)
    print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
