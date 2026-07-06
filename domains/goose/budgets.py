"""GOOSE (IEC 61850-8-1) budgets — the dimension-specific verdict layer.

The core harness measures latency and sizes agnostically; this module turns those
into GOOSE pass/fail verdicts against the two binding constraints:

  LATENCY  : Type 1A (trip) transfer time = 3 ms  (IEC 61850-5, perf class TT6).
             Compute share judged at p99 (worst-case frame).
  SIZE     : one non-fragmented Ethernet frame, ~1500 B payload ceiling.
             GOOSE does not fragment; no jumbo frames assumed.

Signed-frame accounting: 14 B Ethernet header + 8 B GOOSE transport header
+ APDU (~107 B for a single-boolean trip dataset) + signature.
"""

LATENCY_BUDGET_MS = 3.0          # IEC 61850-5 TT6
ETH_PAYLOAD_CEILING = 1500       # bytes; no jumbo frames
ETH_HEADER = 14
GOOSE_HEADER = 8
DEFAULT_APDU = 107               # single-boolean trip APDU (goosePdu, BER)


def frame_bytes(sig_bytes: int, apdu_bytes: int = DEFAULT_APDU) -> int:
    """Total on-air bytes of a signed GOOSE frame (no FCS, no VLAN tag)."""
    return ETH_HEADER + GOOSE_HEADER + apdu_bytes + sig_bytes


def fits_single_frame(sig_bytes: int, apdu_bytes: int = DEFAULT_APDU) -> bool:
    return frame_bytes(sig_bytes, apdu_bytes) - ETH_HEADER <= ETH_PAYLOAD_CEILING


def meets_latency(sign_p99_ms: float, verify_p99_ms: float) -> bool:
    """Worst-case publisher sign + subscriber verify within the 3 ms budget."""
    return sign_p99_ms + verify_p99_ms <= LATENCY_BUDGET_MS
