"""Encode-method brute force (PLAN §7.5).

When the header ``bCryptMethod`` is unknown/untrusted, or decoded data blocks do
not yield a valid Heap-on-Node, trial-decode a probe data block with each of
{NONE, PERMUTE, CYCLIC} ([MS-PST] §5.1/§5.2) and score the plaintext for:

  * the HN signature byte ``bSig == 0xEC`` at block offset +2 ([MS-PST] §2.3.1.2),
  * a recognizable ``bClientSig`` (PC 0xBC / TC 0x7C / BTH 0xB5) at +3,
  * a plausible run of MAPI property tags (prop_type in the documented ranges).

The max-scoring method wins; ties prefer the simpler method (NONE < PERMUTE <
CYCLIC).  This reuses :func:`pstforensic.ndb.crypt.decode_block` so the decode
math is the single source of truth.

NOTE (Appendix A H21 / §0.5): the PERMUTE/CYCLIC substitution tables are
UNVERIFIED against a real Outlook block, and the synth oracle's encode/decode
are functional inverses *by construction*.  Detection therefore proves we pick
the method that round-trips a synth block, NOT the absolute decode direction of
a proprietary sample — the caller emits ``UNVERIFIED_CONST`` accordingly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..exceptions import WarnCode, WarningSink
from ..ltp.heap import HN_CLIENT_PC, HN_CLIENT_TC, HN_SIG
from ..ndb.crypt import decode_block
from ..proptypes import PropType
from ..variant import CRYPT_CYCLIC, CRYPT_NONE, CRYPT_PERMUTE

# bClientSig values that confirm a real LTP heap ([MS-PST] §2.3.1.2).
_HN_CLIENT_BTH = 0xB5
_KNOWN_CLIENT_SIGS = (HN_CLIENT_PC, HN_CLIENT_TC, _HN_CLIENT_BTH)

# Known PropType base values (drop the MV flag) — a plausible-tag heuristic.
_KNOWN_PTYPES = {int(p) for p in PropType}


@dataclass
class EncodeGuess:
    """Result of :func:`detect_encode_method` (PLAN §7.5)."""

    crypt_method: int
    score: float
    plaintext: bytes
    hn_sig_ok: bool
    client_sig_ok: bool


def _score_plaintext(plain: bytes) -> tuple[float, bool, bool]:
    """Score decoded bytes for HN/MAPI plausibility (PLAN §7.5).

    Returns ``(score, hn_sig_ok, client_sig_ok)``.  The HN signature is the
    strongest single signal (weight 0.6); a known bClientSig adds 0.3; a run of
    plausible property types in the would-be BTH region adds up to 0.1.
    """
    if len(plain) < 4:
        return 0.0, False, False
    hn_sig_ok = plain[2] == HN_SIG
    client_sig_ok = plain[3] in _KNOWN_CLIENT_SIGS
    score = 0.0
    if hn_sig_ok:
        score += 0.6
    if client_sig_ok:
        score += 0.3
    # Plausible MAPI tag run: sample 16-bit prop types from the body.
    sampled = 0
    plausible = 0
    for off in range(12, min(len(plain) - 1, 12 + 64), 2):
        ptype = int.from_bytes(plain[off:off + 2], "little") & 0x0FFF
        sampled += 1
        if ptype in _KNOWN_PTYPES:
            plausible += 1
    if sampled:
        score += 0.1 * (plausible / sampled)
    return score, hn_sig_ok, client_sig_ok


def detect_encode_method(probe_block: bytes, bid: int, *,
                         sink: Optional[WarningSink] = None
                         ) -> Optional[EncodeGuess]:
    """Brute-force the crypt method for a probe data block (PLAN §7.5).

    Args:
        probe_block: The encoded ``cb`` payload bytes of a data block known to
            hold an HN (e.g. a message/folder PC).
        bid: The block's BID (CYCLIC is keyed by it — [MS-PST] §5.2).
        sink: Optional sink; ``ENCODE_GUESSED`` is emitted on a match.

    Returns:
        The best-scoring :class:`EncodeGuess`, or ``None`` if no method produced
        a recognizable HN.  Ties prefer the simpler method (NONE first).
    """
    sink = sink if sink is not None else WarningSink()
    best: Optional[EncodeGuess] = None
    for method in (CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC):
        plain = decode_block(probe_block, method, bid)
        score, hn_ok, client_ok = _score_plaintext(plain)
        if best is None or score > best.score:
            best = EncodeGuess(crypt_method=method, score=score,
                               plaintext=plain, hn_sig_ok=hn_ok,
                               client_sig_ok=client_ok)
    if best is None or not best.hn_sig_ok:
        return None
    sink.warn(WarnCode.ENCODE_GUESSED,
              f"crypt_method={best.crypt_method} score={best.score:.2f}",
              where="encode_detect")
    sink.warn(WarnCode.UNVERIFIED_CONST,
              "PERMUTE/CYCLIC decode direction is round-trip-only against the "
              "synth oracle; absolute decode of a real Outlook block is "
              "UNVERIFIED (Appendix A H21)",
              where="encode_detect")
    return best
