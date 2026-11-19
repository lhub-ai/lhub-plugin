#!/usr/bin/env python3
"""lhub.py — the LHUB agent kit: buy and sell services on an LHUB marketplace from one file.

Usage (full docs: /docs/agents.md and /docs/sell.md on the marketplace host):

    pip install cryptography
    python lhub.py init
    python lhub.py find --category digital_services/code/review
    python lhub.py hire --listing <id> --input ./myfile.py --max-price 1.00
    python lhub.py result --deal <id> --out ./review.md
    python lhub.py accept --deal <id>

Selling (add-agent-seller-door D-10):

    python lhub.py sell --category digital_services/text/summarization \\
        --title "Summarizer" --summary "Summarizes a text file" \\
        --price 0.10 --unit file
    python lhub.py listings
    python lhub.py inbox                  # one poll: countersign + fetch funded inputs
    python lhub.py deliver <deal_id> ./out.md
    python lhub.py serve --exec "wc -l"   # loop: run a command per funded job
    python lhub.py retire <listing_id>

Design (add-agent-front-door D-11):

  * ONE file, Python >= 3.10, ONE runtime dependency (``cryptography``);
    HTTP via the standard library only.
  * Key at ``$LHUB_KIT_HOME/agent.pem`` (default ``~/.lhub-kit``), mode 0600.
    The identity is a P-256 ``did:key``; signatures are ES256 compact JWS.
  * In-file JCS (RFC 8785) — proven against the repo's frozen cross-language
    vector (``shared/go/dealartifact/testdata/vector-v1``).
  * A minimal MCP Streamable-HTTP client (initialize → notifications/initialized
    → tools/call) with transparent re-handshake when the bridge restarts
    (sessions are in-memory server-side — R-AFD-3). Request ids are unique
    across processes sharing the cached session; response bodies are capped.
  * Retryable refusals (harden-public-sandbox D-4: ``rate_limited``,
    ``upstream_unavailable``) are told apart from final ones: ``serve`` backs
    off on them and one-shot commands report the code. The MCP stdio server
    returns a kit failure as the same JSON object the CLI prints.
  * ``hire`` is not resumable: every run opens a new deal (escrow's OpenDeal
    has no idempotency key). A ``hire`` that fails after its deal opened
    prints that ``deal_id``, the ``stage`` reached (``opened`` / ``proposed``
    / ``agreed``) and a ``next_step``: run ``status --deal <id>`` before
    hiring again, or a second deal may be agreed and funded too.
  * Machine-readable JSON on stdout; human hints on stderr; non-zero exit with
    a one-line reason on failure.

Security posture (the server enforces everything independently — SEC-1; the
kit's checks are conveniences that keep you from signing something wrong):

  * ``hire`` signs ONLY bytes it derived itself: it validates the agreement
    template's content, canonicalizes that content with its OWN JCS and signs
    those bytes. The server-supplied ``canonical_b64``/``sha256`` are used
    purely as a cross-check — any mismatch means refuse, unsigned (D-5).
  * ``result`` reports a deliverable as delivered only when its SHA-256 equals
    the provider's proof hash (D-4).
  * ``lhub.py mcp``'s file tools are confined to the input root
    (add-claude-code-plugin D-1). ``hire``/``deliver`` read and ``get_result``
    writes (counterparty bytes) only inside it, never through ``..``, never
    under a path component starting with ``.`` (``.env``, ``.ssh/``,
    ``.git/hooks``, ``.claude/``) or holding an invisible/format character,
    and never inside the kit home (matched by filesystem identity, so a
    letter-case variant on a case-insensitive volume is refused too);
    ``get_result`` also never writes ``CLAUDE.md``, ``CLAUDE.local.md`` or
    ``AGENTS.md``, nor the toolchain config files ``uv.toml``,
    ``pyproject.toml``, ``setup.cfg``, ``pip.conf`` and ``requirements*.txt``
    (any case, any depth). All three refuse outright when the root is the
    home directory, a folder above it, or a filesystem root. A refused path
    fails before any network call, read or write. The CLI is unconfined: a
    human types its paths.
  * ``budget set`` is an OWNER action (REG-4): it refuses non-interactive use
    without ``--i-am-the-owner``, prints the owner-authorization notice, writes
    a durable audit line, and is never exposed through ``lhub.py mcp`` (D-12).
  * ``sell`` signs ONLY bytes it built itself: the listing core and the
    activate action are assembled locally and canonicalized with the kit's own
    JCS before signing. The bridge never supplies bytes a seller signs (F4-4).
  * ``inbox`` countersigns a buyer proposal only after ALL seller checks pass
    (seller-door D-10, ported from the house agent's countersign.py); any
    failure means NO signature, a one-line reason, and no retry for the same
    proposal sha. Counterparty-controlled bytes can only ever REFUSE, never
    crash: hostile proposals (lone surrogates, pathological nesting) are
    refused at parse, and a per-item fail-safe keeps one bad item from
    killing the ``inbox``/``serve`` poll loop (sec B-1).
  * ``serve --exec`` runs the seller's OWN configured command with no shell;
    the untrusted job input is passed as a file path argument, never
    interpolated, and the child gets a minimal environment and a bounded,
    capped stdout.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import contextlib
import functools
import hashlib
import hmac
import http.client
import inspect
import ipaddress
import json
import os
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, NamedTuple, NoReturn

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
except ImportError:  # pragma: no cover - exercised only in bare environments
    sys.stdout.write('{"error": "missing dependency: pip install cryptography"}\n')
    sys.stderr.write("error: the kit needs the `cryptography` package: pip install cryptography\n")
    sys.exit(1)

KIT_VERSION = "0.3.2"
# The User-Agent on every request the kit sends. Kit._http_post, the kit's one
# urllib entry point, stamps it over anything a caller passes, so no call site
# can omit, blank or replace it. urllib's default ("Python-urllib/3.x") is
# refused by the Cloudflare edge in front of lhub.ai (HTTP 403, error code
# 1010). Kit 0.3.1 sent that default on the two plain-HTTP surfaces (the
# registration envelope and mandate intake, both used by `budget set`).
USER_AGENT = f"lhub-kit/{KIT_VERSION}"

# --- wire constants (stable contracts; see docs/agents.md served by the bridge) ---
DEFAULT_BASE_URL = "http://localhost:8092"
ENV_BASE_URL = "LHUB_URL"
ENV_KIT_HOME = "LHUB_KIT_HOME"
DEFAULT_KIT_HOME = "~/.lhub-kit"
# The directory that bounds the `lhub mcp` server's file tools: `hire` and
# `deliver` read only under it (sec S4-2), and `get_result` writes only under
# it (add-claude-code-plugin D-1). Defaults to the server's working directory
# at start; the CLI is unaffected.
ENV_INPUT_ROOT = "LHUB_KIT_INPUT_ROOT"
MCP_PATH = "/mcp/v1"
MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_SESSION_HEADER = "Mcp-Session-Id"
MCP_PROTOCOL_HEADER = "MCP-Protocol-Version"
LHUB_SESSION_HEADER = "X-LHUB-Session"
HANDSHAKE_AUDIENCE = "lhub-mcp-session-handshake"

SETTLEMENT_UNIT = "LHUB-DEV"
UNIT_DECIMALS = 6
# The once-per-DID sandbox grant (10.000000 LHUB-DEV) — `budget set` caps
# --total here unless --allow-over-grant is passed (D-12 / sec N-12).
SANDBOX_GRANT_MINOR = 10_000_000
# `budget set --days` ceiling: escrow refuses an Intent Mandate whose `exp`
# lies more than 400 days ahead (escrow mandateHorizonDays,
# harden-public-sandbox task 1.7d). One day of margin keeps a kit clock that
# runs ahead of escrow's inside the horizon (task 3.2).
MAX_BUDGET_DAYS = 399

# The retryable error class (harden-public-sandbox D-4 / D-4a). A retryable
# refusal is still an isError tool result; the bridge marks it with
# `_meta["ai.lhub/error"] = {"code": <code>, "retryable": true}` and starts its
# text with "<code>:", so the text prefix is the fallback when no marker is
# present. A closed set: any other code is an ordinary refusal.
ERROR_META_KEY = "ai.lhub/error"
CODE_RATE_LIMITED = "rate_limited"
CODE_UPSTREAM_UNAVAILABLE = "upstream_unavailable"
RETRYABLE_CODES = (CODE_RATE_LIMITED, CODE_UPSTREAM_UNAVAILABLE)

# Cap on one HTTP response body the kit will read (task 3.2; the read was
# unbounded). Sized from the largest LEGITIMATE responses, not from the
# bridge's 256 KiB request cap: go-sdk sends a typed tool's output twice
# (structuredContent plus the same JSON as text), so a `download_deal_file`
# of a 160 KiB deal file is about 440 KB on the wire, and a 100-hit
# `search_services` page (discovery's maximum) over schema-maximal listings
# written in 4-byte UTF-8 is about 3.8 MB (typical hits measure about 2.3 KB on
# the wire). 8 MiB keeps a 2x margin over that page; anything larger is refused.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# RFC 8785 numbers are IEEE doubles; integers beyond 2^53-1 cannot round-trip.
MAX_SAFE_INT = (1 << 53) - 1

# The deal-artifact v1 content field set (shared/go/dealartifact — frozen).
ARTIFACT_CONTENT_KEYS = frozenset(
    {
        "version",
        "deal_id",
        "request_id",
        "listing_content_hash",
        "buyer_did",
        "provider_did",
        "amount",
        "unit",
        "issued_at",
    }
)
ARTIFACT_VERSION = "1"

# The bridge fences provider-originated text in these markers (SEC-2).
FENCE_OPEN = "[UNTRUSTED-CONTENT]"
FENCE_CLOSE = "[/UNTRUSTED-CONTENT]"

_SHA256_FORM = re.compile(r"sha256:[0-9a-f]{64}")
_ISSUED_AT_FORM = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64_FORM = re.compile(r"[0-9a-f]{64}")
_UUID_FORM = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# --- seller-side constants (add-agent-seller-door D-10) ---

# The OQ-2 deal-file cap: job inputs and deliverables are at most 160 KiB.
DELIVERABLE_CAP_BYTES = 160 * 1024
# The Tier-0 runtime proof method (mirrors the house agent's signing.py).
PROOF_METHOD_SIGNED_OUTPUT_HASH = "signed-output-hash"
# The agree edge's freshness window, mirrored from the bridge's dualsig gate so
# the kit's local accept/refuse line coincides with the authoritative one.
AGREE_MAX_AGE_SECONDS = 24 * 60 * 60
AGREE_FUTURE_SKEW_SECONDS = 30
# serve --exec: per-job wall-clock cap. The listing's turnaround bounds the
# timeout, hard-capped here (D-10).
SERVE_TIMEOUT_CAP_SECONDS = 30 * 60
# serve: transport-failure backoff cap. A bridge restart must not kill the
# seller loop (a dead loop shows as an OFFLINE listing): serve retries at
# interval x 2^n, capped here, reset on the first successful round. A
# retryable refusal (D-4) backs off on the same schedule.
SERVE_BACKOFF_CAP_SECONDS = 5 * 60
# serve: the backoff cap for a `rate_limited` refusal of register_agent (the
# re-handshake after a bridge restart or token expiry re-registers). The
# identity limit's window is 24 h by default (harden-public-sandbox D-2,
# R-HPS-5), so this wait keeps doubling past the transport cap instead of
# re-registering every 5 minutes for a day.
SERVE_IDENTITY_BACKOFF_CAP_SECONDS = 60 * 60
# sell: the waits before each post-sell search check (cumulative 1, 3, 7 and
# 15 s). Indexing is publish-after-commit, and the anonymous-read budget is
# shared per source (anon_read, 120/min), so the check spends at most four
# searches instead of polling every second.
SEARCH_CHECK_WAITS_SECONDS = (1.0, 2.0, 4.0, 8.0)
# serve --exec: stderr kept for the failure record only, tail-truncated.
SERVE_STDERR_CAP_BYTES = 16 * 1024
# Refusal-memory bounds (sec N-1): a counterparty can mint unlimited fresh
# proposal shas, so the memory is capped per deal and overall, oldest evicted
# first. Eviction is safe: an evicted sha is simply re-evaluated on its next
# appearance and re-refused (the checks are deterministic and sign nothing).
REFUSAL_MEMORY_MAX_PER_DEAL = 32
REFUSAL_MEMORY_MAX_TOTAL = 1024
# `pricing.unit` is an identifier so it cannot carry instructions (seller-door D-1).
_UNIT_ID_FORM = re.compile(r"[A-Za-z0-9_.-]{1,32}")
# The core schema's decimal-amount pattern (no leading zeros / "+" / exponents).
_DECIMAL_AMOUNT_FORM = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]{1,6})?")
# The one leaf whose Layer-C extension is NOT generic-task (seller-door D-1).
CODE_REVIEW_CATEGORY = "digital_services/code/review"
# The deal state on which countersigning is possible.
STATE_NEGOTIATING = "NEGOTIATING"

# Deal states at which `hire` stops polling.
HIRE_SUCCESS_STATES = frozenset(
    {"IN_FULFILLMENT", "AWAITING_CONFIRM", "PROOF_SUBMITTED", "RELEASED"}
)
HIRE_DEAD_STATES = frozenset({"CANCELLED", "REFUNDED", "DISPUTED", "SPLIT"})

# How far a `hire` got, reported when it fails after its deal opened (task 3.2
# fix-pass, arch F1). `hire` is not resumable and escrow's OpenDeal carries no
# idempotency key, so running `hire` again opens a SECOND deal; a countersigning
# seller plus a standing budget could then agree and fund both. Each stage is
# the last step the kit saw CONFIRMED:
HIRE_STAGE_OPENED = "opened"  # start_negotiation returned the deal id
HIRE_STAGE_PROPOSED = "proposed"  # propose_agreement returned: our signature is stored
HIRE_STAGE_AGREED = "agreed"  # a poll saw the deal past NEGOTIATING (DEAL_AGREED/FUNDED)

# did:key multicodec prefix for compressed P-256 (0x1200 varint -> 0x80 0x24).
_P256_MULTICODEC = bytes((0x80, 0x24))
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

HTTP_TIMEOUT_SECONDS = 30.0


class KitError(Exception):
    """A one-line, operator-actionable failure. Commands exit 1 with it.

    ``context`` holds extra machine-readable fields a flow attaches on the way
    out (today: the deal a failed ``hire`` left behind); ``main`` prints them
    after ``error`` (and ``code``/``retryable``) and never lets them replace
    those. Empty by default, so most failures print exactly what they did.
    """

    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        self.context: dict[str, Any] = {}


class KitRefusal(KitError):
    """The kit refused to sign (a convenience check failed BEFORE signing)."""


class KitTransportError(KitError):
    """The marketplace could not be reached (network down, timeout, bridge
    restarting, 5xx). Retryable: the request never produced a usable answer.
    ``serve`` backs off and keeps polling on this class and on
    :class:`KitRetryableError`; every other ``KitError`` (tool refusals,
    contract errors) still ends the loop."""


class KitRetryableError(KitError):
    """The marketplace answered with a retryable refusal (D-4): ``rate_limited``
    or ``upstream_unavailable``. Refused for now, not for good.

    Deliberately NOT a :class:`KitTransportError` subclass, so code that
    catches ``KitTransportError`` keeps its exact behaviour (D-4: "callers are
    unchanged"); ``serve`` catches both. The message keeps the
    ``<tool>: <code>: …`` form, so substring checks on the code still work.
    """

    def __init__(self, message: str, *, code: str, tool: str) -> None:
        super().__init__(message)
        self.code = code
        self.tool = tool

    @property
    def identity_window(self) -> bool:
        """True for a rate-limited registration: the identity limit's window
        is long (24 h by default), so waiting minutes does not help."""
        return self.code == CODE_RATE_LIMITED and self.tool == "register_agent"


class KitFailure(KitError):
    """A failure that still carries a machine-readable payload for stdout."""

    def __init__(self, reason: str, payload: dict[str, Any]) -> None:
        super().__init__(reason)
        self.payload = payload


class TransportSessionLost(Exception):
    """Internal: the MCP transport session died (bridge restart); re-initialize."""


# ---------------------------------------------------------------------------
# JCS — RFC 8785 canonical JSON, in-file (D-11), proven against the repo's
# frozen vector. Deliberate narrowing: floats are REFUSED (LHUB money is
# integer minor units; no signed LHUB payload carries a float, and a float
# arriving in one is a fail-closed signal, not something to serialize).
# ---------------------------------------------------------------------------

_JCS_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _JCS_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):  # bool handled above
        if abs(v) > MAX_SAFE_INT:
            raise KitError(f"integer {v} exceeds the JSON safe range (2^53-1)")
        return str(v)
    if isinstance(v, float):
        raise KitError("floats are refused in signed payloads (amounts are integer minor units)")
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs_value(item) for item in v) + "]"
    if isinstance(v, dict):
        for key in v:
            if not isinstance(key, str):
                raise KitError("JSON object keys must be strings")
        # RFC 8785: keys sort by UTF-16 code units — utf-16-be bytes compare
        # exactly that way (surrogate pairs included).
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs_value(val) for k, val in items) + "}"
    raise KitError(f"unsupported type in signed payload: {type(v).__name__}")


def jcs_canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 (JCS) canonical UTF-8 bytes of ``obj``."""
    return _jcs_value(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# did:key (P-256) + ES256 compact JWS.
# ---------------------------------------------------------------------------


def _b58encode(raw: bytes) -> str:
    num = int.from_bytes(raw, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _BASE58_ALPHABET[rem] + encoded
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + encoded


def did_key_from_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """Encode a P-256 public key as ``did:key:z…`` (multicodec 0x1200, compressed point)."""
    numbers = public_key.public_numbers()
    prefix = 0x02 if numbers.y % 2 == 0 else 0x03
    compressed = bytes((prefix,)) + numbers.x.to_bytes(32, "big")
    return "did:key:z" + _b58encode(_P256_MULTICODEC + compressed)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_es256(key: ec.EllipticCurvePrivateKey, payload: bytes, *, kid: str) -> str:
    """Sign ``payload`` as an ES256 compact JWS (header ``{"alg","kid","typ"}``).

    The signature is the JOSE fixed-width R||S form (RFC 7518 §3.4), verifiable
    by LHUB's Go-side ``signing.Verify`` (which checks ``alg`` and ignores
    extra protected headers such as ``kid``).
    """
    header = json.dumps({"alg": "ES256", "kid": kid, "typ": "JWT"}, separators=(",", ":"))
    signing_input = f"{_b64url(header.encode('ascii'))}.{_b64url(payload)}".encode("ascii")
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + _b64url(sig)


# ---------------------------------------------------------------------------
# JWS verification (seller countersign check 6) — a faithful port of the house
# agent's ``signing.verify_jws_es256_canonical`` + ``decode_did_key_p256``.
# The verifier NEVER trusts the embedded payload: the caller re-derives the
# canonical bytes itself and this function byte-compares before any signature
# check, so a JWS over attacker-chosen bytes fails the compare even when its
# signature is internally valid.
# ---------------------------------------------------------------------------

# Strict base64url segment alphabet (RFC 7515 §2): no '+', '/', '='. Enforced
# BEFORE decoding because the stdlib decoder silently discards non-alphabet
# characters, so two different strings could otherwise decode identically.
_B64URL_SEGMENT_FORM = re.compile(r"[A-Za-z0-9_-]*")


def _b58decode(encoded: str) -> bytes:
    """base58btc-decode (the exact inverse of ``_b58encode``)."""
    num = 0
    for ch in encoded:
        index = _BASE58_ALPHABET.find(ch)
        if index < 0:
            raise KitError(f"invalid base58 character {ch!r} in did:key body")
        num = num * 58 + index
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    leading_ones = len(encoded) - len(encoded.lstrip("1"))
    return b"\x00" * leading_ones + body


def decode_did_key_p256(did: str) -> ec.EllipticCurvePublicKey:
    """Decode a P-256 ``did:key`` to its public key (did:key P-256 signers only)."""
    prefix = "did:key:z"
    if not did.startswith(prefix):
        raise KitError(f"not a base58btc did:key: {did!r}")
    raw = _b58decode(did[len(prefix) :])
    if len(raw) != len(_P256_MULTICODEC) + 33:
        raise KitError("did:key payload has the wrong length for a p256-pub key")
    if raw[: len(_P256_MULTICODEC)] != _P256_MULTICODEC:
        raise KitError("did:key multicodec prefix is not p256-pub")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), raw[len(_P256_MULTICODEC) :]
        )
    except ValueError as exc:
        raise KitError(f"did:key does not encode a valid P-256 point: {exc}") from exc


def _b64url_decode(segment: str) -> bytes:
    """Strictly base64url-decode a no-padding JWS segment (refuses '+', '/', '=')."""
    if _B64URL_SEGMENT_FORM.fullmatch(segment) is None:
        raise KitError("invalid base64url JWS segment: non-alphabet character")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError) as exc:  # binascii.Error extends ValueError
        raise KitError(f"invalid base64url JWS segment: {exc}") from exc


def verify_jws_es256_canonical(*, did: str, jws: str, expected_canonical: bytes) -> None:
    """Verify a compact ES256 JWS from ``did`` whose payload IS ``expected_canonical``.

    Checks, in order (any failure raises :class:`KitError`): compact 3-segment
    form; header alg == ES256 and no ``crit`` (this verifier implements no
    extensions — RFC 7515 §4.1.11); payload == ``expected_canonical``
    (constant-time); the raw 64-byte JOSE R||S verifies under the P-256 key
    resolved from ``did``.
    """
    parts = jws.split(".")
    if len(parts) != 3:
        raise KitError("JWS is not in compact three-segment form")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header_obj = json.loads(_b64url_decode(header_b64))
    except ValueError as exc:
        raise KitError(f"JWS protected header is not valid JSON: {exc}") from exc
    if not isinstance(header_obj, dict) or header_obj.get("alg") != "ES256":
        raise KitError("JWS protected header alg is not ES256")
    if "crit" in header_obj:
        raise KitError("JWS protected header carries crit (no extensions are supported)")

    payload = _b64url_decode(payload_b64)
    if not hmac.compare_digest(payload, expected_canonical):
        raise KitError("JWS payload does not equal the expected canonical bytes")

    raw_signature = _b64url_decode(signature_b64)
    if len(raw_signature) != 64:
        raise KitError("JWS signature is not a raw 64-byte JOSE R||S")
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    try:
        der_signature = encode_dss_signature(r, s)
    except ValueError as exc:
        raise KitError(f"JWS signature R/S out of range: {exc}") from exc

    public_key = decode_did_key_p256(did)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise KitError("JWS signature does not verify under the signer's did:key") from exc


# ---------------------------------------------------------------------------
# Money — integer minor units internally; decimal strings at the CLI boundary.
# ---------------------------------------------------------------------------


def parse_amount_minor(text: str, *, decimals: int = UNIT_DECIMALS) -> int:
    """Convert a decimal string ("1.00") to integer minor units, exactly (no floats)."""
    cleaned = text.strip()
    match = re.fullmatch(r"([0-9]+)(?:\.([0-9]{1," + str(decimals) + r"}))?", cleaned)
    if match is None:
        raise KitError(
            f'invalid amount {text!r}: use a plain decimal string like "1.00"'
            f" (at most {decimals} decimal places)"
        )
    whole = str(match.group(1))
    frac = str(match.group(2) or "")
    scale = int(10**decimals)
    return int(whole) * scale + int(frac.ljust(decimals, "0") or "0")


def format_display(
    minor: int, unit: str = SETTLEMENT_UNIT, *, decimals: int = UNIT_DECIMALS
) -> str:
    """Render minor units as a display string ("0.50 LHUB-DEV")."""
    sign = "-" if minor < 0 else ""
    whole, frac = divmod(abs(minor), int(10**decimals))
    frac_str = f"{frac:0{decimals}d}".rstrip("0")
    if len(frac_str) < 2:
        frac_str = frac_str.ljust(2, "0")
    return f"{sign}{whole}.{frac_str} {unit}"


def render_decimal(minor: int, *, decimals: int = UNIT_DECIMALS) -> str:
    """Render minor units as the core schema's canonical decimal string ("1", "0.05")."""
    if minor < 0:
        raise KitError("a listing amount cannot be negative")
    whole, frac = divmod(minor, int(10**decimals))
    if frac == 0:
        return str(whole)
    return f"{whole}." + f"{frac:0{decimals}d}".rstrip("0")


def require_uuid(value: str, *, what: str = "deal id") -> str:
    """Return ``value`` lowercased iff it is a well-formed UUID; refuse otherwise.

    Deal and listing ids become path components under ``$LHUB_KIT_HOME``; a
    UUID-checked id contains no separators or traversal tokens (seller-door
    D-10 hardening).
    """
    if _UUID_FORM.fullmatch(value) is None:
        raise KitError(f"{what} {value!r} is not a UUID; refusing to use it")
    return value.lower()


def _parse_rfc3339_any(text: str) -> float | None:
    """RFC 3339 with Z or a numeric offset -> unix seconds; ``None`` if malformed or naive."""
    cleaned = text.strip()
    if cleaned.endswith(("Z", "z")):
        # Python 3.10's fromisoformat does not accept a trailing Z.
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def unfence(text: str) -> str:
    """Strip the bridge's untrusted-content fence when present (value unchanged otherwise)."""
    stripped = text.strip()
    if stripped.startswith(FENCE_OPEN) and stripped.endswith(FENCE_CLOSE):
        inner = stripped[len(FENCE_OPEN) : len(stripped) - len(FENCE_CLOSE)]
        return inner.strip("\n").strip()
    return text


def sha256_ref(data: bytes) -> str:
    """The LHUB content reference form: ``sha256:`` + lowercase hex SHA-256."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def note(message: str) -> None:
    """A human hint — stderr only; stdout stays machine-readable JSON."""
    sys.stderr.write(message + "\n")


def _ascii_clip(text: str, limit: int = 400) -> str:
    """Bounded PRINTABLE-ASCII text (sec B-1 / R2 N-1 sanitiser).

    Counterparty-derived text can be huge, non-encodable, or carry control
    characters (newlines, terminal escapes): non-ASCII goes through
    backslashreplace, control characters are hex-escaped, and the result is
    truncated — safe for stderr, JSON stdout and the refusal memory alike.
    """
    safe = text.encode("ascii", "backslashreplace").decode("ascii")
    safe = "".join(ch if 0x20 <= ord(ch) < 0x7F else f"\\x{ord(ch):02x}" for ch in safe)
    return safe[:limit]


def _fail_safe_reason(exc: BaseException) -> str:
    """An ASCII-safe one-line reason for a fail-safe boundary record (sec B-1).

    Unexpected exception text can itself carry counterparty-derived characters
    that stderr/JSON encoding would choke on (the very failure mode the
    boundary guards), so the reason is forced to bounded, printable ASCII.
    """
    return _ascii_clip(f"unexpected {type(exc).__name__}: {exc}", 300)


# ---------------------------------------------------------------------------
# Template validation + artifact assembly (D-5 step 2 — the security-critical
# path). Pure apart from the final signing call so tests can drive every
# refusal and prove nothing is signed on any mismatch.
# ---------------------------------------------------------------------------


def validate_template_and_sign(
    template: Mapping[str, Any],
    *,
    own_did: str,
    deal_id: str,
    request_id: str,
    max_price_minor: int,
    deal_provider: str | None,
    pinned_provider: str | None,
    key: ec.EllipticCurvePrivateKey,
) -> tuple[str, bytes]:
    """Validate an agreement template, then sign ONLY our own JCS of its content.

    Every check runs BEFORE any signature is produced; any failure raises
    :class:`KitRefusal` and nothing is signed. The server-supplied
    ``canonical_b64`` and ``sha256`` are cross-checks only — the signed bytes
    are always this function's own canonicalization of the validated content.

    Returns ``(artifact_b64, canonical_bytes)`` where ``artifact_b64`` is the
    std-base64 single-signature envelope ``{content, signatures:[{signer,jws}]}``
    that ``propose_agreement`` takes (D-14).
    """
    content = template.get("content")
    if not isinstance(content, dict):
        raise KitRefusal("refusing to sign: template has no content object")

    keys = set(content.keys())
    if keys != ARTIFACT_CONTENT_KEYS:
        extra = sorted(keys - ARTIFACT_CONTENT_KEYS)
        missing = sorted(ARTIFACT_CONTENT_KEYS - keys)
        raise KitRefusal(
            "refusing to sign: template content field set is not deal-artifact v1"
            f" (missing={missing} unexpected={extra})"
        )

    for field in ARTIFACT_CONTENT_KEYS - {"amount"}:
        if not isinstance(content[field], str):
            raise KitRefusal(f"refusing to sign: template content.{field} is not a string")

    amount = content["amount"]
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise KitRefusal("refusing to sign: template amount is not an integer (minor units)")
    if amount < 0 or amount > MAX_SAFE_INT:
        raise KitRefusal(f"refusing to sign: template amount {amount} is out of range")

    if content["version"] != ARTIFACT_VERSION:
        raise KitRefusal(
            f'refusing to sign: template content.version is {content["version"]!r}, not "1"'
        )
    if content["deal_id"] != deal_id:
        raise KitRefusal("refusing to sign: template deal_id does not match the opened deal")
    if content["request_id"] != request_id:
        raise KitRefusal(
            "refusing to sign: template request_id does not equal the job input hash"
            f" (template {content['request_id']!r}, input {request_id!r})"
        )
    if content["buyer_did"] != own_did:
        raise KitRefusal("refusing to sign: template buyer_did is not this agent's DID")
    if deal_provider is None and pinned_provider is None:
        # sdd N2: without any provider anchor the provider check would be
        # vacuous — fail closed, unsigned (mirrors the house agent's posture).
        raise KitRefusal(
            "refusing to sign: no provider anchor — the deal read returned no provider_did"
            " and no --provider was pinned (pass --provider <did> from `find`)"
        )
    if deal_provider is not None and content["provider_did"] != deal_provider:
        raise KitRefusal(
            "refusing to sign: template provider_did does not match the deal's provider"
        )
    if pinned_provider is not None and content["provider_did"] != pinned_provider:
        raise KitRefusal(
            "refusing to sign: template provider_did does not match the provider you pinned"
            f" with --provider ({pinned_provider})"
        )
    if content["unit"] != SETTLEMENT_UNIT:
        raise KitRefusal(
            f"refusing to sign: template unit is {content['unit']!r}, not {SETTLEMENT_UNIT!r}"
        )
    if amount > max_price_minor:
        raise KitRefusal(
            f"refusing to sign: template amount {amount} ({format_display(amount)})"
            f" exceeds your maximum price {max_price_minor} ({format_display(max_price_minor)})"
        )
    if _ISSUED_AT_FORM.fullmatch(content["issued_at"]) is None:
        raise KitRefusal("refusing to sign: template issued_at is not a UTC-Z RFC 3339 timestamp")
    if _HEX64_FORM.fullmatch(content["listing_content_hash"]) is None:
        raise KitRefusal("refusing to sign: template listing_content_hash is not 64 lowercase hex")

    # Self-derived canonical bytes — the ONLY bytes we ever sign (sec B-1).
    canonical = jcs_canonicalize(content)

    # Cross-check the server's claimed canonical form + hash. Any disagreement
    # means the server would verify different bytes than we validated: refuse,
    # unsigned.
    claimed_b64 = template.get("canonical_b64")
    if not isinstance(claimed_b64, str) or not claimed_b64:
        raise KitRefusal("refusing to sign: template carries no canonical_b64 to cross-check")
    try:
        claimed = base64.b64decode(claimed_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise KitRefusal("refusing to sign: template canonical_b64 is not valid base64") from exc
    if claimed != canonical:
        raise KitRefusal(
            "refusing to sign: template canonical bytes differ from our own canonicalization"
            " of the validated content"
        )
    claimed_sha = template.get("sha256")
    if not isinstance(claimed_sha, str) or claimed_sha != hashlib.sha256(canonical).hexdigest():
        raise KitRefusal("refusing to sign: template sha256 does not match the canonical content")

    # All checks passed — sign our own bytes and assemble the one-signature
    # envelope. The content is embedded as the exact canonical bytes so the
    # server re-derives identical canonical form from what we send.
    jws = sign_es256(key, canonical, kid=own_did)
    signatures = json.dumps([{"signer": own_did, "jws": jws}], separators=(",", ":"))
    artifact = b'{"content":' + canonical + b',"signatures":' + signatures.encode("ascii") + b"}"
    return base64.b64encode(artifact).decode("ascii"), canonical


def verify_deliverable(proof_hash: str, data: bytes) -> tuple[bool, str]:
    """Compare deliverable bytes against the proof's ``sha256:<hex>`` reference.

    Returns ``(matches, actual_hash)``. The proof hash must already be
    unfenced and strictly formed (the caller validates the form).
    """
    actual = sha256_ref(data)
    return actual == proof_hash, actual


# ---------------------------------------------------------------------------
# Seller countersign checks (seller-door D-10) — a full port of the house
# agent's countersign.py + cosign.py. Every check runs BEFORE any signature;
# any failure raises :class:`KitRefusal` with a one-line reason and NOTHING is
# signed. The functions are pure so tests can drive every refusal.
# ---------------------------------------------------------------------------


class SellerProposal(NamedTuple):
    """A strictly-parsed buyer proposal: content + its single signature + metadata."""

    content: dict[str, Any]
    signer: str
    jws: str
    issued_at_unix: float
    sha256_hex: str


def _refuse_unencodable_strings(obj: Any) -> None:
    """Refuse any string anywhere in a decoded proposal that UTF-8 cannot encode.

    ``json.loads`` accepts ``\\uD800``-style escapes that decode to LONE
    SURROGATES. Such a string later explodes as :class:`UnicodeEncodeError`
    (NOT a ``KitError``) inside ``jcs_canonicalize`` or a stderr write —
    BEFORE signature verification — escaping the refusal path and killing the
    poll loop (sec B-1). Checked up front over keys and values alike, at any
    depth, iteratively (the nesting bound is ``json.loads``'s own recursion
    guard, so this walk itself can never recurse out of stack).
    """
    stack: list[Any] = [obj]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise KitRefusal(
                    "refusing to countersign: proposal contains a string UTF-8 cannot"
                    " encode (lone surrogate)"
                ) from exc
        elif isinstance(value, dict):
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)


def parse_seller_proposal(data: bytes) -> SellerProposal:
    """Strict-parse downloaded ``agreement_proposal`` bytes (untrusted, SEC-2).

    Mirrors the house agent's ``parse_proposal``: the exact ``{content,
    signatures}`` envelope, the exact v1 content key set (an unknown key —
    the reserved ``acceptance`` included — is refused), exactly ONE signature
    of exactly ``{signer, jws}``, both non-empty strings, with the same type
    guards (bool-before-int on amount, timezone-aware issued_at).

    Counterparty bytes must only ever REFUSE, never crash (sec B-1): a
    too-deeply-nested body (``RecursionError``) and any non-UTF-8-encodable
    string (keys included) are refusals like any other malformed proposal.
    """
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise KitRefusal(f"refusing to countersign: proposal is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise KitRefusal("refusing to countersign: proposal JSON is nested too deeply") from exc
    # Before ANY other look at the object (error messages included): no string
    # that cannot round-trip through UTF-8 gets past this line.
    _refuse_unencodable_strings(obj)
    if not isinstance(obj, dict):
        raise KitRefusal("refusing to countersign: proposal is not a JSON object")
    if set(obj.keys()) != {"content", "signatures"}:
        raise KitRefusal(
            "refusing to countersign: proposal envelope keys must be exactly"
            f" ['content', 'signatures'] (got {sorted(obj.keys())})"
        )

    raw_content = obj["content"]
    if not isinstance(raw_content, dict):
        raise KitRefusal("refusing to countersign: proposal content is not a JSON object")
    if set(raw_content.keys()) != ARTIFACT_CONTENT_KEYS:
        missing = sorted(ARTIFACT_CONTENT_KEYS - set(raw_content.keys()))
        extra = sorted(set(raw_content.keys()) - ARTIFACT_CONTENT_KEYS)
        # Unknown fields include the reserved `acceptance` object — refused in a
        # v1 artifact exactly as the bridge's dualsig gate refuses it.
        raise KitRefusal(
            "refusing to countersign: proposal content field set mismatch"
            f" (missing={missing} extra={extra})"
        )

    for field in ARTIFACT_CONTENT_KEYS - {"amount"}:
        value = raw_content[field]
        if not isinstance(value, str) or not value:
            raise KitRefusal(
                f"refusing to countersign: proposal content.{field} must be a non-empty string"
            )
    if raw_content["version"] != ARTIFACT_VERSION:
        raise KitRefusal(
            f"refusing to countersign: proposal content.version {raw_content['version']!r}"
            f" is not {ARTIFACT_VERSION!r}"
        )

    amount = raw_content["amount"]
    # bool first: bool subclasses int and would otherwise pass (the D-3 guard).
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise KitRefusal("refusing to countersign: proposal content.amount is not a JSON integer")
    if amount < 0 or amount > MAX_SAFE_INT:
        raise KitRefusal(
            f"refusing to countersign: proposal content.amount {amount} not in [0, {MAX_SAFE_INT}]"
        )

    issued_at_unix = _parse_rfc3339_any(raw_content["issued_at"])
    if issued_at_unix is None:
        raise KitRefusal(
            "refusing to countersign: proposal content.issued_at is not a timezone-aware"
            " RFC 3339 timestamp"
        )

    raw_signatures = obj["signatures"]
    if not isinstance(raw_signatures, list) or len(raw_signatures) != 1:
        count = len(raw_signatures) if isinstance(raw_signatures, list) else "non-list"
        raise KitRefusal(
            f"refusing to countersign: proposal must carry exactly one signature (got {count})"
        )
    raw_sig = raw_signatures[0]
    if not isinstance(raw_sig, dict) or set(raw_sig.keys()) != {"signer", "jws"}:
        raise KitRefusal(
            "refusing to countersign: proposal signature must be exactly {signer, jws}"
        )
    signer = raw_sig["signer"]
    jws = raw_sig["jws"]
    if not isinstance(signer, str) or not signer:
        raise KitRefusal("refusing to countersign: proposal signature.signer is not a string")
    if not isinstance(jws, str) or not jws:
        raise KitRefusal("refusing to countersign: proposal signature.jws is not a string")

    return SellerProposal(
        content=dict(raw_content),
        signer=signer,
        jws=jws,
        issued_at_unix=issued_at_unix,
        sha256_hex=hashlib.sha256(data).hexdigest(),
    )


def normalize_deal_record(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the authoritative deal record from a ``get_deal`` payload.

    The record is the comparison source for compare-then-sign (never the
    proposal's own claims). A projection missing any required field cannot be
    compared against, so the mapping fails closed as a refusal. ``amount``
    arrives as the wire's minor-units integer string and becomes an ``int``
    here; ``listing_content_hash`` maps to ``None`` when absent (refused later
    by the binding check — fail-closed, mirroring the house agent).
    """
    out: dict[str, Any] = {}
    for field in ("deal_id", "state", "request_id", "buyer_did", "provider_did", "unit"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise KitRefusal(f"refusing to countersign: the deal read carries no {field}")
        out[field] = unfence(value)
    amount_raw = payload.get("amount")
    if isinstance(amount_raw, str) and amount_raw.isdigit():
        out["amount"] = int(amount_raw, 10)
    elif isinstance(amount_raw, int) and not isinstance(amount_raw, bool):
        out["amount"] = amount_raw
    else:
        raise KitRefusal("refusing to countersign: the deal read carries no integer amount")
    hash_raw = payload.get("listing_content_hash")
    out["listing_content_hash"] = (
        unfence(hash_raw) if isinstance(hash_raw, str) and hash_raw else None
    )
    return out


def check_seller_binding(
    *,
    own_did: str,
    deal: Mapping[str, Any],
    stored: Mapping[str, Any] | None,
    input_present: bool,
) -> None:
    """Seller checks 2 and 3: the listing is OURS and the input is bound.

    D-4a: escrow deals carry no listing UUID, so ownership matches by the
    SEC-3 pinned ``listing_content_hash``. ``stored`` is the listings-store
    entry resolved BY that hash (``{listing_id, content_hash, core}``), or
    ``None`` when no stored signed core carries it.
    """
    if deal["provider_did"] != own_did:
        raise KitRefusal("refusing to countersign: the deal's provider is not this kit's DID")
    pinned = deal.get("listing_content_hash")
    if not isinstance(pinned, str) or not pinned:
        # Fail-closed: a projection without the platform's pinned value cannot
        # cover the listing pin in the compare (house-agent posture).
        raise KitRefusal("refusing to countersign: the deal read carries no listing_content_hash")
    if stored is None:
        raise KitRefusal(
            "refusing to countersign: no stored signed core carries the deal's"
            " listing_content_hash (not a listing version this kit sold)"
        )
    if pinned != stored.get("content_hash"):
        # Defensive: the caller resolved `stored` by this hash, so a mismatch
        # means a corrupted store entry — refuse, never sign.
        raise KitRefusal(
            "refusing to countersign: the deal's pinned listing_content_hash does not equal"
            " the stored signed core's hash"
        )
    if _SHA256_FORM.fullmatch(str(deal["request_id"])) is None:
        raise KitRefusal("refusing to countersign: the deal's request_id is not sha256-bound")
    if not input_present:
        raise KitRefusal(
            "refusing to countersign: the deal has no job_input file"
            " (an input-less deal could become an unfulfillable funded job)"
        )


def check_proposal_freshness(issued_at_unix: float, *, now_unix: float) -> None:
    """Seller check 5: the agree edge's freshness window, strictly mirrored."""
    if issued_at_unix > now_unix + AGREE_FUTURE_SKEW_SECONDS:
        raise KitRefusal("refusing to countersign: proposal issued_at is in the future")
    if now_unix - issued_at_unix > AGREE_MAX_AGE_SECONDS:
        raise KitRefusal("refusing to countersign: proposal is stale (older than 24h)")


def check_content_matches_deal(
    *, content: Mapping[str, Any], deal: Mapping[str, Any], own_did: str
) -> None:
    """Seller check 7: EVERY content field equals the platform's deal record.

    All mismatches are collected and reported in one reason (the cosign.py
    discipline), not first-fail-only.
    """
    if content["provider_did"] != own_did:
        raise KitRefusal("refusing to countersign: proposal provider_did is not this kit's DID")
    mismatches = [
        name
        for name in (
            "deal_id",
            "request_id",
            "buyer_did",
            "provider_did",
            "amount",
            "unit",
            "listing_content_hash",
        )
        if content[name] != deal[name]
    ]
    if content["version"] != ARTIFACT_VERSION:
        mismatches.append("version")
    if mismatches:
        raise KitRefusal(
            "refusing to countersign: proposal content disagrees with the deal record on: "
            + ", ".join(mismatches)
        )


def check_price_terms(*, amount: int, pricing: Mapping[str, Any], proposal_unit: str) -> None:
    """Seller check 8: the amount matches the STORED listing's price terms.

    - the amount is an integer in ``[1, MAX_SAFE_INT]``;
    - ``flat``: amount == price;
    - ``per_unit``: amount is a positive integer multiple of price, at or above
      any ``min_charge``; or ``min_charge > price`` and amount == ``min_charge``
      (the only floor amount the bridge can derive);
    - the proposal's ``unit`` is the SETTLEMENT currency: it must equal the
      stored listing's ``pricing.currency`` and is never compared with the
      billable ``pricing.unit`` (arch R2 B-1).
    """
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise KitRefusal("refusing to countersign: amount is not an integer")
    if amount < 1 or amount > MAX_SAFE_INT:
        raise KitRefusal(f"refusing to countersign: amount {amount} is outside [1, {MAX_SAFE_INT}]")
    currency = pricing.get("currency")
    if proposal_unit != currency:
        raise KitRefusal(
            f"refusing to countersign: proposal unit {proposal_unit!r} is not the stored"
            f" listing's settlement currency {currency!r}"
        )
    try:
        price = parse_amount_minor(str(pricing.get("amount") or ""))
    except KitError as exc:
        raise KitRefusal(f"refusing to countersign: stored listing price unusable: {exc}") from exc
    min_charge: int | None = None
    raw_min = pricing.get("min_charge")
    if isinstance(raw_min, str) and raw_min:
        try:
            min_charge = parse_amount_minor(raw_min)
        except KitError as exc:
            raise KitRefusal(
                f"refusing to countersign: stored listing min_charge unusable: {exc}"
            ) from exc

    model = pricing.get("model")
    if model == "flat":
        if amount != price:
            raise KitRefusal(
                f"refusing to countersign: flat amount {amount} != listing price {price}"
            )
        return
    if model != "per_unit":
        raise KitRefusal(f"refusing to countersign: unknown stored pricing model {model!r}")
    if price < 1:
        raise KitRefusal("refusing to countersign: stored listing unit price is zero")

    is_positive_multiple = amount >= price and amount % price == 0
    meets_floor = min_charge is None or amount >= min_charge
    is_exact_floor = min_charge is not None and min_charge > price and amount == min_charge
    if (is_positive_multiple and meets_floor) or is_exact_floor:
        return
    if is_positive_multiple:
        raise KitRefusal(
            f"refusing to countersign: amount {amount} is below the listing min_charge {min_charge}"
        )
    raise KitRefusal(
        f"refusing to countersign: amount {amount} is neither a positive multiple of the"
        f" unit price {price} nor exactly the min_charge floor"
    )


def validate_budget_days(days: int) -> None:
    """Bound ``--days`` to [1, MAX_BUDGET_DAYS] (task 3.2).

    Escrow refuses a mandate whose ``exp`` lies more than 400 days ahead; the
    kit stops one day short so a clock running ahead of escrow's cannot push a
    budget past the horizon after the owner has already confirmed it.
    """
    if days < 1 or days > MAX_BUDGET_DAYS:
        raise KitError(
            f"--days must be between 1 and {MAX_BUDGET_DAYS} (escrow refuses a budget that"
            " expires more than 400 days ahead; the kit keeps one day of margin)"
        )


def validate_budget_totals(total_minor: int, *, allow_over_grant: bool) -> None:
    """Cap --total at the sandbox grant unless explicitly overridden (D-12)."""
    if total_minor > SANDBOX_GRANT_MINOR and not allow_over_grant:
        raise KitError(
            f"budget total {format_display(total_minor)} exceeds the sandbox grant"
            f" {format_display(SANDBOX_GRANT_MINOR)}; pass --allow-over-grant if you really"
            " hold more than the grant"
        )


def fallback_next_step(state: str) -> str:
    """A buyer-role next step when the server response carries none (pre-D-8.4 bridges)."""
    table = {
        "NEGOTIATING": "waiting for the provider to countersign; re-run: python lhub.py status --deal <id>",
        "DEAL_AGREED": "agreed; funding is in progress",
        "AWAITING_CONFIRM": "awaiting the owner's confirmation for THIS deal; a budget set now does not cover it — the owner can pre-authorize FUTURE deals with: python lhub.py budget set",
        "FUNDED": "funded; fulfilment starts next",
        "IN_FULFILLMENT": "the provider is working; poll: python lhub.py result --deal <id> --out <file>",
        "PROOF_SUBMITTED": "download and verify the deliverable: python lhub.py result --deal <id> --out <file>",
        "RELEASED": "complete — funds released to the provider",
        "DISPUTED": "in dispute; arbitration decides",
        "CANCELLED": "cancelled; open a new deal if still needed",
        "REFUNDED": "refunded to the buyer",
        "SPLIT": "resolved by arbitration with a split",
    }
    return table.get(state, "re-run: python lhub.py status --deal <id>")


# ---------------------------------------------------------------------------
# SSE / JSON-RPC plumbing for the MCP Streamable-HTTP transport.
# ---------------------------------------------------------------------------


def parse_sse(raw: bytes) -> list[dict[str, Any]]:
    """Extract JSON messages from a text/event-stream body (data: lines per event)."""
    messages: list[dict[str, Any]] = []
    text = raw.decode("utf-8", errors="replace")
    for record in re.split(r"\r?\n\r?\n", text):
        data_lines: list[str] = []
        for line in record.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].removeprefix(" "))
        if not data_lines:
            continue
        try:
            parsed = json.loads("\n".join(data_lines))
        except ValueError:
            continue
        if isinstance(parsed, dict):
            messages.append(parsed)
    return messages


def _header_get(headers: Mapping[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""


def _snippet(body: bytes, limit: int = 300) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _redact_url(url: str) -> str:
    """``url`` with any userinfo (``user:pass@``) removed: the only form of the
    marketplace URL an error or note may show, since kit errors can reach an LLM
    through ``lhub.py mcp`` (sec re-review NIT 2)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:  # e.g. a malformed IPv6 literal: drop anything before an '@'
        return re.sub(r"//[^/?#]*@", "//", url)
    if "@" not in parts.netloc:
        return url
    return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def _url_credentials(url: str) -> tuple[str, ...]:
    """The credential strings a credentialed ``url`` can leak into an exception
    text, longest first: its userinfo and password, raw and percent-decoded.

    urllib keeps the userinfo in the request's host and decodes it, so its own
    errors can carry it (e.g. ``InvalidURL("nonnumeric port: 's3cret@host'")``
    for a URL without a port); the kit masks these before rendering one.
    """
    try:
        netloc = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ()
    userinfo = netloc.rpartition("@")[0]
    password = userinfo.partition(":")[2]
    found = {userinfo, urllib.parse.unquote(userinfo), password, urllib.parse.unquote(password)}
    return tuple(sorted((item for item in found if item), key=len, reverse=True))


def _read_capped(resp: Any, url: str) -> bytes:
    """Read one HTTP response body, refusing anything over ``MAX_RESPONSE_BYTES``.

    A declared Content-Length over the cap is refused before any body byte is
    read; otherwise at most cap + 1 bytes are read, so an undeclared
    (chunked or streamed) oversize body costs the kit no more than the cap.
    An oversize response is a plain ``KitError``, not a transport error: the
    server did answer, with something the kit will not hold, and waiting does
    not change that.
    """
    cap = MAX_RESPONSE_BYTES
    shown = _redact_url(url)
    refusal = f"the response from {shown} is larger than the kit's {cap}-byte cap; refusing it"
    headers = getattr(resp, "headers", None)
    declared = headers.get("Content-Length") if headers is not None else None
    if declared is not None:
        try:
            declared_length = int(declared)
        except ValueError:
            declared_length = -1  # malformed: the bounded read below still applies
        if declared_length > cap:
            raise KitError(refusal)
    data = resp.read(cap + 1)
    if not isinstance(data, bytes):
        raise KitError(f"the response from {shown} carried no readable body")
    if len(data) > cap:
        raise KitError(refusal)
    return data


def _tool_error_text(result: Mapping[str, Any]) -> str:
    parts: list[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
    return " ".join(parts) or "tool call failed"


def retryable_code(result: Mapping[str, Any]) -> str | None:
    """The D-4 retryable code of an ``isError`` tool result, or None.

    The marker is ``result["_meta"]["ai.lhub/error"]`` (D-4a). The kit's raw
    JSON-RPC client sees ``_meta`` as a plain key of the decoded result object
    (go-sdk serialises ``CallToolResult.Meta`` as ``"_meta"``), so the marker is
    authoritative when it names a known code with ``retryable: true``. Without
    such a marker the text-prefix match decides (D-4: the text begins with the
    code token, then ``:``), for a proxy or bridge build that drops ``_meta``.
    Unknown codes are never retryable.
    """
    meta = result.get("_meta")
    marker = meta.get(ERROR_META_KEY) if isinstance(meta, dict) else None
    if isinstance(marker, dict):
        code = marker.get("code")
        if marker.get("retryable") is True and isinstance(code, str) and code in RETRYABLE_CODES:
            return code
    text = _tool_error_text(result)
    for known in RETRYABLE_CODES:
        if text.startswith(known + ":"):
            return known
    return None


def _retryable_hint(tool: str, code: str) -> str:
    """A one-line operator hint appended to a retryable refusal's message."""
    if code == CODE_RATE_LIMITED and tool == "register_agent":
        return (
            "registration is rate-limited; the identity limit's window is long (24 h by"
            " default), so this can last up to a day and retrying sooner will not help."
            " A DID that was registered before stays registered"
        )
    if code == CODE_RATE_LIMITED:
        return "a marketplace rate limit applies to this call; back off and retry later"
    return "a marketplace backing service is temporarily unavailable; retry later"


def _tool_payload(result: Mapping[str, Any]) -> dict[str, Any]:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if not isinstance(text, str):
                    continue
                try:
                    parsed = json.loads(text)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
    return {}


# ---------------------------------------------------------------------------
# The kit client: key store, MCP transport, LHUB session, plain-HTTP surfaces.
# ---------------------------------------------------------------------------


def kit_home_from_env() -> Path:
    """The kit home: ``$LHUB_KIT_HOME``, default ``~/.lhub-kit`` (not resolved).

    The ONE place it is computed, so where ``Kit.from_env`` keeps the key and
    what the MCP file tools refuse to touch cannot drift apart.
    """
    return Path(os.environ.get(ENV_KIT_HOME) or DEFAULT_KIT_HOME).expanduser()


class Kit:
    """One agent identity talking to one LHUB bridge."""

    def __init__(self, base_url: str, home: Path) -> None:
        invalid = f"invalid LHUB URL {_redact_url(base_url)!r}: must be http(s)://host[:port]"
        try:
            parsed = urllib.parse.urlparse(base_url)
        except ValueError as exc:  # e.g. a malformed IPv6 literal
            raise KitError(invalid) from exc
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise KitError(invalid)
        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname or ""):
            # sec S4-3: bearer session tokens and signatures would travel in
            # the clear to a remote host.
            note(
                f"warning: plain http to non-loopback host {parsed.hostname!r} — session"
                " tokens travel unencrypted; prefer https"
            )
        self.base_url = base_url.rstrip("/")
        # Credentials a user:pass@ URL carries, masked in every rendered error
        # (exception texts from urllib can embed them; sec re-review NIT 2).
        self._url_credentials = _url_credentials(base_url)
        self.home = home
        self.key_path = home / "agent.pem"
        self._key: ec.EllipticCurvePrivateKey | None = None
        self._did: str | None = None
        self._mcp_session_id: str | None = None
        self._protocol_version = MCP_PROTOCOL_VERSION
        self._session_token: str | None = None
        self._session_expires = ""
        # The DID the cached session was minted for (sec S4-5): validated
        # against the key's DID in ensure_key; a mismatch drops the cache.
        self._session_did: str | None = None
        # JSON-RPC request ids (task 3.2). MCP forbids reusing a request id
        # within a session, and the MCP session is persisted in session.json,
        # so several processes can share it (serve beside a manual inbox, a
        # canary run beside a supply reading). Each instance draws a random
        # 64-bit prefix and counts under it, so ids never repeat across
        # processes (2^-64 collision odds per pair) and an orphaned id is
        # never re-sent. See _next_id for the wire form.
        self._rpc_prefix = secrets.token_hex(8)
        self._rpc_seq = 0
        self._registration: dict[str, Any] | None = None
        self._in_handshake = False
        self._load_session_file()

    @classmethod
    def from_env(cls, base_url: str | None = None) -> Kit:
        url = base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL
        return cls(url, kit_home_from_env())

    # ----- key + identity -----

    def ensure_key(self) -> ec.EllipticCurvePrivateKey:
        """Load the agent key, creating it (0600, dir 0700) on first use."""
        if self._key is not None:
            return self._key
        if self.key_path.exists():
            mode = self.key_path.stat().st_mode & 0o777
            if mode & 0o077:
                # sec S4-4: a group/other-readable private key is a local
                # exposure; warn (the key still works — fixing is the owner's call).
                note(
                    f"warning: the agent key at {self.key_path} is group/other-readable"
                    f" (mode {mode:03o}); run: chmod 600 {self.key_path}"
                )
            data = self.key_path.read_bytes()
            try:
                loaded = serialization.load_pem_private_key(data, password=None)
            except (ValueError, TypeError) as exc:
                raise KitError(
                    f"cannot read the agent key at {self.key_path}: not a PEM private key"
                ) from exc
            if not isinstance(loaded, ec.EllipticCurvePrivateKey) or not isinstance(
                loaded.curve, ec.SECP256R1
            ):
                raise KitError(f"the agent key at {self.key_path} is not a P-256 EC key")
            self._key = loaded
        else:
            self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
            self._key = key
            note(f"created a new P-256 agent key at {self.key_path} (mode 0600)")
        self._did = did_key_from_public_key(self._key.public_key())
        # sec S4-5: a cached session minted for a different DID (the key file
        # was replaced, or the cache was copied in) must not be reused.
        if self._session_did is not None and self._session_did != self._did:
            note("cached session belonged to a different DID; discarding it")
            self._session_token = None
            self._session_expires = ""
            self._mcp_session_id = None
            self._session_did = None
        return self._key

    @property
    def did(self) -> str:
        if self._did is None:
            self.ensure_key()
        if self._did is None:  # pragma: no cover - ensure_key always derives it
            raise KitError("internal: agent key loaded but no DID derived")
        return self._did

    def sign_payload(self, payload: Mapping[str, Any]) -> str:
        """JCS-canonicalize ``payload`` and ES256-sign the canonical bytes."""
        key = self.ensure_key()
        return sign_es256(key, jcs_canonicalize(dict(payload)), kid=self.did)

    # ----- session persistence (token + transport handles; 0600) -----

    @property
    def _session_file(self) -> Path:
        return self.home / "session.json"

    def _load_session_file(self) -> None:
        try:
            raw = self._session_file.read_text(encoding="utf-8")
        except OSError:
            return
        try:
            data = json.loads(raw)
        except ValueError:
            return
        if not isinstance(data, dict) or data.get("base_url") != self.base_url:
            return
        token = data.get("session_token")
        expires = data.get("expires_at")
        stored_did = data.get("did")
        if (
            isinstance(token, str)
            and token
            and isinstance(expires, str)
            and _rfc3339_to_unix(expires) > time.time() + 60
            # sec S4-5: a cached token is only adoptable when the file names
            # the DID it was minted for; ensure_key cross-checks it against
            # the key's DID and drops the cache on mismatch.
            and isinstance(stored_did, str)
            and stored_did
        ):
            self._session_token = token
            self._session_expires = expires
            self._session_did = stored_did
        sid = data.get("mcp_session_id")
        if isinstance(sid, str) and sid:
            self._mcp_session_id = sid
        proto = data.get("protocol_version")
        if isinstance(proto, str) and proto:
            self._protocol_version = proto

    def _save_session_file(self) -> None:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = {
            "base_url": self.base_url,
            "did": self.did,
            "mcp_session_id": self._mcp_session_id,
            "protocol_version": self._protocol_version,
            "session_token": self._session_token,
            "expires_at": self._session_expires,
        }
        fd = os.open(self._session_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self._session_did = self.did

    # ----- HTTP -----

    def _http_post(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        # Every request leaves through here (tests/test_user_agent.py pins this as
        # the only urllib call site), so the User-Agent is set here and nowhere
        # else. A caller's own User-Agent, in any spelling or empty, is dropped.
        sent = {name: value for name, value in headers.items() if name.lower() != "user-agent"}
        sent["User-Agent"] = USER_AGENT
        # S310: the URL is always self.base_url + a fixed path; the scheme is
        # restricted to http/https in __init__, so file:/custom schemes cannot reach here.
        request = urllib.request.Request(url, data=body, headers=sent, method="POST")  # noqa: S310
        try:
            # Scheme restricted to http/https in __init__ — safe for urlopen.
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as resp:  # noqa: S310
                data = _read_capped(resp, url)
                return resp.status, dict(resp.headers.items()), data
        except urllib.error.HTTPError as exc:
            data = _read_capped(exc, url)
            hdrs = dict(exc.headers.items()) if exc.headers is not None else {}
            return exc.code, hdrs, data
        except TimeoutError as exc:
            raise KitTransportError(
                f"request to {_redact_url(url)} timed out after {HTTP_TIMEOUT_SECONDS:.0f}s"
            ) from exc
        except urllib.error.URLError as exc:
            raise KitTransportError(
                f"cannot reach {_redact_url(url)}: {self._scrub(str(exc.reason))}"
            ) from exc
        except (http.client.HTTPException, OSError) as exc:
            # The connection died mid-response (bridge restart while reading:
            # RemoteDisconnected/IncompleteRead/raw socket errors) — transport,
            # retryable, same as not reaching the host at all. urllib's own
            # text can embed a credentialed host (InvalidURL), hence _scrub.
            raise KitTransportError(
                f"connection to {_redact_url(url)} failed: {self._scrub(str(exc))}"
            ) from exc

    def _scrub(self, text: str) -> str:
        """``text`` with the marketplace URL's credentials (if any) masked."""
        for secret in self._url_credentials:
            text = text.replace(secret, "***")
        return text

    # ----- MCP transport -----

    def _next_id(self) -> str:
        """The next JSON-RPC request id: ``<16 hex>-<n>``, unique across processes.

        A string, not a number: the bridge decodes number ids as int64, and a
        random 64-bit number could overflow it. At most 16 + 1 + 20 = 37
        bytes, far inside the bridge's 128-byte call-id bound.
        """
        self._rpc_seq += 1
        return f"{self._rpc_prefix}-{self._rpc_seq}"

    def _mcp_headers(self, *, with_session: bool) -> dict[str, str]:
        # No User-Agent here: _http_post sets it on every request.
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._mcp_session_id:
            headers[MCP_SESSION_HEADER] = self._mcp_session_id
            headers[MCP_PROTOCOL_HEADER] = self._protocol_version
        if with_session and self._session_token:
            headers[LHUB_SESSION_HEADER] = self._session_token
        return headers

    def _post_rpc(
        self, message: dict[str, Any], *, with_session: bool
    ) -> tuple[int, dict[str, str], list[dict[str, Any]]]:
        body = json.dumps(message).encode("utf-8")
        url = self.base_url + MCP_PATH
        status, headers, raw = self._http_post(
            url, body, self._mcp_headers(with_session=with_session)
        )
        if status == 404 and (b"session not found" in raw or b"session is closing" in raw):
            raise TransportSessionLost
        content_type = _header_get(headers, "Content-Type")
        messages: list[dict[str, Any]] = []
        if "text/event-stream" in content_type:
            messages = parse_sse(raw)
        elif raw.strip():
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                messages = [parsed]
            elif isinstance(parsed, list):
                messages = [m for m in parsed if isinstance(m, dict)]
        return status, headers, messages

    def _rpc_response(
        self, method: str, params: dict[str, Any], *, with_session: bool
    ) -> dict[str, Any]:
        rpc_id = self._next_id()
        message = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
        status, _headers, messages = self._post_rpc(message, with_session=with_session)
        for msg in messages:
            if msg.get("id") == rpc_id and ("result" in msg or "error" in msg):
                return msg
        if status >= 500:
            # A 5xx with no JSON-RPC body is a bridge/proxy mid-restart
            # (502/503 HTML and the like): transport, retryable.
            raise KitTransportError(
                f"MCP endpoint returned HTTP {status} with no JSON-RPC response for {method}"
            )
        raise KitError(
            f"MCP endpoint returned HTTP {status} with no JSON-RPC response for {method}"
        )

    def _reset_transport(self) -> None:
        self._mcp_session_id = None

    def _ensure_transport(self) -> None:
        if self._mcp_session_id:
            return
        rpc_id = self._next_id()
        message = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "lhub-kit", "version": KIT_VERSION},
            },
        }
        status, headers, messages = self._post_rpc(message, with_session=False)
        response: dict[str, Any] | None = None
        for msg in messages:
            if msg.get("id") == rpc_id and ("result" in msg or "error" in msg):
                response = msg
                break
        if response is None:
            message_text = (
                f"MCP initialize failed (HTTP {status}); is an LHUB bridge at"
                f" {_redact_url(self.base_url)}?"
            )
            if status >= 500:
                raise KitTransportError(message_text)  # bridge/proxy mid-restart
            raise KitError(message_text)
        if "error" in response:
            err = response["error"]
            detail = err.get("message") if isinstance(err, dict) else str(err)
            raise KitError(f"MCP initialize refused: {detail}")
        session_id = _header_get(headers, MCP_SESSION_HEADER)
        if not session_id:
            raise KitError("MCP initialize returned no Mcp-Session-Id header")
        self._mcp_session_id = session_id
        result = response.get("result")
        if isinstance(result, dict):
            proto = result.get("protocolVersion")
            if isinstance(proto, str) and proto:
                self._protocol_version = proto
        # Complete the handshake with the initialized notification (202 expected).
        notify = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        notify_status, _h, _m = self._post_rpc(notify, with_session=False)
        if notify_status not in (200, 202, 204):
            text = f"MCP initialized notification refused (HTTP {notify_status})"
            if notify_status >= 500:
                raise KitTransportError(text)
            raise KitError(text)
        # Persist the fresh transport handle so the next process skips the
        # dead-session round-trip (only once an identity exists to stamp it with).
        if self._did is not None:
            self._save_session_file()

    # ----- tool calls with transparent recovery (R-AFD-3) -----

    def call_tool(
        self, name: str, arguments: dict[str, Any], *, with_session: bool = True, _recover: int = 2
    ) -> dict[str, Any]:
        """Call an MCP tool and return its JSON payload.

        Recovers transparently from a dead transport session ("session not
        found" after a bridge restart) and from an expired LHUB session
        (auth-required tool error) by re-initializing / re-handshaking, at
        most ``_recover`` times.
        """
        try:
            self._ensure_transport()
            response = self._rpc_response(
                "tools/call", {"name": name, "arguments": arguments}, with_session=with_session
            )
        except TransportSessionLost:
            if _recover <= 0:
                # Session churn past the recovery budget = a flapping bridge:
                # transport-class, so `serve` backs off instead of dying.
                raise KitTransportError("the MCP transport session kept dying; giving up") from None
            note("MCP transport session lost (bridge restart?); re-initializing")
            self._reset_transport()
            return self.call_tool(name, arguments, with_session=with_session, _recover=_recover - 1)

        if "error" in response:
            err = response["error"]
            detail = err.get("message") if isinstance(err, dict) else str(err)
            raise KitError(f"{name}: {detail}")

        result = response.get("result")
        if not isinstance(result, dict):
            raise KitError(f"{name}: malformed tool result")
        if result.get("isError"):
            text = _tool_error_text(result)
            if (
                with_session
                and _recover > 0
                and not self._in_handshake
                and "authentication required" in text
            ):
                note("LHUB session expired; re-running the handshake")
                self._session_token = None
                self.handshake()
                return self.call_tool(
                    name, arguments, with_session=with_session, _recover=_recover - 1
                )
            code = retryable_code(result)
            if code is not None:
                # D-4: refused for now, not for good. `serve` backs off on
                # this class; one-shot commands surface the code.
                raise KitRetryableError(
                    f"{name}: {text} ({_retryable_hint(name, code)})", code=code, tool=name
                )
            raise KitError(f"{name}: {text}")
        return _tool_payload(result)

    # ----- LHUB session handshake + registration -----

    def handshake(self) -> dict[str, Any]:
        """Mint an LHUB session (challenge → sign → complete) and register the DID.

        The signed payload is the JCS of ``{"aud","did","nonce"}`` — note the
        challenge RESPONSE names the field ``audience`` but the SIGNED payload
        uses ``aud`` (OQ-1). The audience is pinned client-side: a server
        offering any other audience is refused, unsigned.
        """
        self._in_handshake = True
        try:
            did = self.did
            challenge = self.call_tool("auth_challenge", {"agent_did": did}, with_session=False)
            nonce = challenge.get("nonce")
            if not isinstance(nonce, str) or not nonce:
                raise KitError("auth_challenge returned no nonce")
            audience = challenge.get("audience")
            if isinstance(audience, str) and audience and audience != HANDSHAKE_AUDIENCE:
                raise KitRefusal(
                    f"refusing to sign handshake: server audience {audience!r} is not the pinned"
                    f" {HANDSHAKE_AUDIENCE!r}"
                )
            jws = self.sign_payload({"aud": HANDSHAKE_AUDIENCE, "did": did, "nonce": nonce})
            session = self.call_tool(
                "auth_complete",
                {"agent_did": did, "nonce": nonce, "signature": jws},
                with_session=False,
            )
            token = session.get("session_token")
            if not isinstance(token, str) or not token:
                raise KitError("auth_complete returned no session token")
            self._session_token = token
            expires = session.get("expires_at")
            self._session_expires = expires if isinstance(expires, str) else ""
            # Register (idempotent). Any successful registration — fresh or
            # replay — also triggers the sandbox grant server-side (D-8.8).
            registration = self.call_tool("register_agent", {})
            self._registration = registration
            self._save_session_file()
            return registration
        finally:
            self._in_handshake = False

    def ensure_session(self) -> None:
        """Make sure a usable LHUB session exists (load, else handshake)."""
        self.ensure_key()
        if self._session_token:
            return
        self.handshake()

    @property
    def registration(self) -> dict[str, Any] | None:
        return self._registration

    # ----- plain-HTTP surfaces (registration envelope + mandate intake) -----

    def register_envelope(self) -> int:
        """Idempotent self-registration via ``POST /v1/agents/register`` (201 or 200)."""
        self.ensure_key()
        envelope = {"agent_did": self.did, "nonce": f"lhub-kit-register-{secrets.token_hex(16)}"}
        body = jcs_canonicalize(envelope)
        jws = sign_es256(self.ensure_key(), body, kid=self.did)
        status, _headers, raw = self._http_post(
            self.base_url + "/v1/agents/register",
            body,
            {
                "Content-Type": "application/json",
                "X-LHUB-Register-DID": self.did,
                "X-LHUB-Register-Signature": jws,
            },
        )
        if status not in (200, 201):
            raise KitError(f"registration failed (HTTP {status}): {self._scrub(_snippet(raw))}")
        return status

    def submit_intent_mandate(self, claims: Mapping[str, Any]) -> str:
        """Sign + submit an Intent Mandate; returns the escrow-issued mandate id.

        Wire shape per the bridge's mandate intake: the inner ``mandate_jws``
        signs the claims; the outer body ``{owner_did, mandate_jws, nonce}``
        is JCS-canonicalized and signed into ``X-LHUB-Mandate-Signature``.
        """
        key = self.ensure_key()
        mandate_jws = sign_es256(key, jcs_canonicalize(dict(claims)), kid=self.did)
        intake = {
            "owner_did": self.did,
            "mandate_jws": mandate_jws,
            "nonce": f"lhub-kit-budget-{secrets.token_hex(16)}",
        }
        body = jcs_canonicalize(intake)
        envelope_jws = sign_es256(key, body, kid=self.did)
        status, _headers, raw = self._http_post(
            self.base_url + "/v1/mandates/intent",
            body,
            {
                "Content-Type": "application/json",
                "X-LHUB-Mandate-DID": self.did,
                "X-LHUB-Mandate-Signature": envelope_jws,
            },
        )
        if status != 201:
            raise KitError(f"mandate intake failed (HTTP {status}): {self._scrub(_snippet(raw))}")
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise KitError("mandate intake returned a non-JSON body") from exc
        mandate_id = parsed.get("id") if isinstance(parsed, dict) else None
        if not isinstance(mandate_id, str) or not mandate_id:
            raise KitError("mandate intake returned no mandate id")
        return mandate_id

    # ----- audit (durable owner-action record) -----

    def append_audit(self, entry: dict[str, Any]) -> Path:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.home / "audit.log"
        line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
        # sec S4-4: owner-only file from the first byte (O_APPEND keeps the
        # durable append-only discipline; fsync before returning).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return path

    # ----- seller-side local state (seller-door D-10) -----

    @property
    def listings_dir(self) -> Path:
        """Signed listing cores this kit sells at — the countersign comparison source."""
        return self.home / "listings"

    @property
    def jobs_dir(self) -> Path:
        """Per-deal job directories (funded inputs, failure/delivery markers)."""
        return self.home / "jobs"

    @property
    def pending_dir(self) -> Path:
        """Pending registry operations: idempotency keys stored for retries."""
        return self.home / "pending"

    def _write_private_json(self, path: Path, payload: Mapping[str, Any]) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)

    def _write_private_json_atomic(self, path: Path, payload: Mapping[str, Any]) -> None:
        """Owner-only JSON write via tmp + ``os.replace`` (sec N-1).

        A reader never sees a torn file: the replace is atomic on POSIX. No
        fsync — losing the newest write on a crash only costs a re-refusal.
        """
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp-{secrets.token_hex(8)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def write_job_marker(self, path: Path, payload: Mapping[str, Any]) -> None:
        """Write a per-job marker file (failed.json / delivered.json), owner-only."""
        self._write_private_json(path, payload)

    def store_listing(self, listing_id: str, content_hash: str, core: Mapping[str, Any]) -> Path:
        """Persist the signed core as the terms this kit sells at (D-10)."""
        safe_id = require_uuid(listing_id, what="listing id")
        path = self.listings_dir / f"{safe_id}.json"
        self._write_private_json(
            path, {"listing_id": safe_id, "content_hash": content_hash, "core": dict(core)}
        )
        return path

    def load_listing(self, listing_id: str) -> dict[str, Any] | None:
        """Load a stored listing entry, or ``None`` when this kit never sold it.

        The id is UUID-checked before it becomes a path component; a non-UUID
        id is simply "not ours".
        """
        if _UUID_FORM.fullmatch(listing_id) is None:
            return None
        path = self.listings_dir / f"{listing_id.lower()}.json"
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        return data

    def find_listing_by_hash(self, content_hash: str) -> dict[str, Any] | None:
        """Find the stored signed core whose content hash is ``content_hash``.

        D-4a: escrow deals carry no listing UUID, only the SEC-3 pinned
        ``listing_content_hash`` — a content hash identifies one listing
        version uniquely, so ownership matching is by hash. ``None`` when no
        stored core carries it (this kit never sold that listing version).
        """
        if not content_hash or _HEX64_FORM.fullmatch(content_hash) is None:
            return None
        try:
            paths = sorted(self.listings_dir.glob("*.json"))
        except OSError:
            return None
        for path in paths:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict) and data.get("content_hash") == content_hash:
                return data
        return None

    def load_pending(self, name: str) -> dict[str, Any] | None:
        """Read a pending registry operation (its stored idempotency keys)."""
        try:
            data = json.loads((self.pending_dir / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def save_pending(self, name: str, payload: Mapping[str, Any]) -> None:
        self._write_private_json(self.pending_dir / f"{name}.json", payload)

    def clear_pending(self, name: str) -> None:
        (self.pending_dir / f"{name}.json").unlink(missing_ok=True)

    # Refusal memory: a failed seller check is never retried with the same
    # proposal sha (seller-door D-10).
    @property
    def _refusals_path(self) -> Path:
        return self.home / "refusals.json"

    def _load_refusals(self) -> dict[str, Any]:
        try:
            data = json.loads(self._refusals_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def refusal_reason(self, deal_id: str, proposal_sha256: str) -> str | None:
        entry = self._load_refusals().get(f"{deal_id}:{proposal_sha256}")
        if isinstance(entry, dict) and isinstance(entry.get("reason"), str):
            return str(entry["reason"])
        return None

    def record_refusal(self, deal_id: str, proposal_sha256: str, reason: str) -> None:
        """Record a refusal so the same proposal sha is never re-evaluated.

        BOUNDED (sec N-1): at most ``REFUSAL_MEMORY_MAX_PER_DEAL`` entries per
        deal and ``REFUSAL_MEMORY_MAX_TOTAL`` overall, oldest evicted first
        (the fresh record always survives). Eviction and concurrent loss are
        both SAFE degradations: an absent sha is simply re-evaluated on its
        next appearance and re-refused — the checks are deterministic and
        sign nothing on failure. The write is atomic (tmp + ``os.replace``)
        so a reader never sees a torn file; concurrent kit processes are
        last-writer-wins (an overwritten entry re-refuses, by design).

        The stored reason is clipped to bounded printable ASCII (sec R2 N-1):
        refusal messages can embed counterparty-sized text (hostile key
        lists, repr'd values), and the memory must not grow with it.
        """
        refusals = self._load_refusals()
        new_key = f"{deal_id}:{proposal_sha256}"
        refusals[new_key] = {
            "reason": _ascii_clip(reason),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        def entry_ts(key: str) -> str:
            entry = refusals.get(key)
            ts = entry.get("ts") if isinstance(entry, dict) else None
            return ts if isinstance(ts, str) else ""

        def evict_oldest(keys: list[str], cap: int) -> None:
            excess = len(keys) - cap
            if excess <= 0:
                return
            keys.sort(key=lambda key: (entry_ts(key), key))
            dropped = 0
            for key in keys:
                if dropped >= excess:
                    break
                if key == new_key:  # the record being written always survives
                    continue
                del refusals[key]
                dropped += 1

        prefix = f"{deal_id}:"
        evict_oldest(
            [key for key in refusals if key.startswith(prefix)], REFUSAL_MEMORY_MAX_PER_DEAL
        )
        evict_oldest(list(refusals), REFUSAL_MEMORY_MAX_TOTAL)
        self._write_private_json_atomic(self._refusals_path, refusals)

    def job_dir(self, deal_id: str) -> Path:
        """Materialise ``$LHUB_KIT_HOME/jobs/<uuid-checked deal_id>`` (no-follow)."""
        safe_id = require_uuid(deal_id)
        self.jobs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        node = self.jobs_dir / safe_id
        if node.is_symlink():
            raise KitError(f"refusing to use a pre-existing symlink as a job dir: {node}")
        node.mkdir(mode=0o700, exist_ok=True)
        return node


def _is_loopback_host(host: str) -> bool:
    """True for localhost and loopback literals (127.0.0.0/8, ::1)."""
    lowered = host.lower()
    if lowered == "localhost":
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _rfc3339_to_unix(text: str) -> float:
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z", text.strip()
    )
    if match is None:
        return 0.0
    y, mo, d, h, mi, s = (int(g) for g in match.groups())
    return float(calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)))


# ---------------------------------------------------------------------------
# Flows shared by the CLI and the MCP stdio server.
# ---------------------------------------------------------------------------


def _deal_view(deal: Mapping[str, Any]) -> dict[str, Any]:
    """A compact buyer view of a get_deal payload, with kit-side fallbacks."""
    state = str(deal.get("state") or "")
    amount = deal.get("amount")
    display = deal.get("display")
    if not isinstance(display, str) or not display:
        if isinstance(amount, str) and amount.lstrip("-").isdigit():
            display = format_display(int(amount), str(deal.get("unit") or SETTLEMENT_UNIT))
        elif isinstance(amount, int) and not isinstance(amount, bool):
            display = format_display(amount, str(deal.get("unit") or SETTLEMENT_UNIT))
        else:
            display = None
    next_step = deal.get("next_step")
    if not isinstance(next_step, str) or not next_step:
        next_step = fallback_next_step(state)
    view: dict[str, Any] = {
        "deal_id": deal.get("deal_id"),
        "state": state,
        "amount": amount,
        "unit": deal.get("unit") or SETTLEMENT_UNIT,
        "decimals": deal.get("decimals", UNIT_DECIMALS),
        "display": display,
        "next_step": next_step,
    }
    return view


def _hire_left_deal(deal_id: str, stage: str) -> dict[str, Any]:
    """The fields a ``hire`` failure carries once its deal exists (arch F1)."""
    return {
        "deal_id": deal_id,
        "stage": stage,
        "next_step": (
            f"before hiring again, run: python lhub.py status --deal {deal_id}; this hire"
            f" already opened that deal (stage: {stage}), and running hire again opens a"
            " second deal"
        ),
    }


def do_hire(
    kit: Kit,
    *,
    listing_id: str,
    input_bytes: bytes,
    max_price_minor: int,
    pinned_provider: str | None,
    quantity: int | None,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, Any]:
    """The one-call buy flow (D-13): open → upload input → validate+sign → propose → wait.

    Not resumable: escrow's OpenDeal carries no idempotency key, so every call
    opens a new deal. A failure AFTER the deal opened therefore carries that
    deal in ``KitError.context`` (``deal_id``, the ``stage`` reached and a
    ``next_step`` to check it before hiring again — ``_hire_left_deal``), and
    the timeout/dead-state ``KitFailure`` payloads carry ``stage`` too. A
    failure before any deal opened is unchanged.
    """
    request_ref = sha256_ref(input_bytes)
    kit.ensure_session()

    args: dict[str, Any] = {"listing_id": listing_id, "request_ref": request_ref}
    if quantity is not None:
        args["quantity"] = quantity
    try:
        opened = kit.call_tool("start_negotiation", args)
    except KitError as exc:
        # R-AFD-16: per-unit listings need a quantity; flat listings refuse one.
        # The kit cannot know the model up front, so it defaults quantity to 1
        # exactly when the listing turns out to be per-unit.
        # The "quantity" substring trigger is PINNED to the bridge source
        # (D-14: the bridge's quantity refusals keep the word "quantity"):
        # services/protocol-bridge/internal/mcp/tools.go,
        # classifyStartNegotiationError — "quantity must be an integer
        # between 1 and <MaxQuantityPerDeal>" and "quantity is not applicable
        # for this listing's flat pricing". A bridge rewording is an
        # orchestrator amendment to D-14, not a silent kit drift
        # (tests/test_hire_hygiene.py pins both messages verbatim).
        if quantity is None and "quantity" in str(exc):
            note("per-unit listing: defaulting --quantity to 1 (R-AFD-16)")
            quantity = 1
            args["quantity"] = 1
            opened = kit.call_tool("start_negotiation", args)
        else:
            raise
    deal_id = opened.get("deal_id")
    if not isinstance(deal_id, str) or not deal_id:
        raise KitError("start_negotiation returned no deal_id")
    note(f"deal {deal_id} opened in state {opened.get('state')}")

    # From here on a deal exists: any failure must say which one (arch F1).
    stage = HIRE_STAGE_OPENED
    try:
        uploaded = kit.call_tool(
            "upload_deal_file",
            {
                "deal_id": deal_id,
                "kind": "job_input",
                "content_b64": base64.b64encode(input_bytes).decode("ascii"),
            },
        )
        uploaded_sha = unfence(str(uploaded.get("sha256") or ""))
        if uploaded_sha and uploaded_sha not in (request_ref, request_ref.removeprefix("sha256:")):
            raise KitError(
                f"job input upload came back with hash {uploaded_sha!r}, expected {request_ref!r}"
            )
        note("job input uploaded")

        live = kit.call_tool("get_deal", {"deal_id": deal_id})
        provider = live.get("provider_did")
        deal_provider = unfence(provider) if isinstance(provider, str) and provider else None

        template = kit.call_tool("get_agreement_template", {"deal_id": deal_id})
        # R-AFD-17: state the exact quote — the effective amount, min_charge floor
        # included — BEFORE anything is signed. --max-price still caps the signature.
        template_content = template.get("content")
        if isinstance(template_content, dict):
            quoted = template_content.get("amount")
            if isinstance(quoted, int) and not isinstance(quoted, bool):
                note(
                    f"quote before signing: {format_display(quoted)} total for quantity"
                    f" {quantity if quantity is not None else 1} (any listing min_charge floor"
                    " is already included; signing only if within --max-price"
                    f" {format_display(max_price_minor)})"
                )
        artifact_b64, _canonical = validate_template_and_sign(
            template,
            own_did=kit.did,
            deal_id=deal_id,
            request_id=request_ref,
            max_price_minor=max_price_minor,
            deal_provider=deal_provider,
            pinned_provider=pinned_provider,
            key=kit.ensure_key(),
        )
        # A failure ON this call leaves the stage at "opened": the proposal may or
        # may not have been stored, which `status` tells apart.
        kit.call_tool("propose_agreement", {"deal_id": deal_id, "artifact_b64": artifact_b64})
        stage = HIRE_STAGE_PROPOSED
        note("proposal signed and submitted; waiting for the provider to countersign")

        deadline = time.monotonic() + timeout_seconds
        last = live
        state = str(live.get("state") or "NEGOTIATING")
        while time.monotonic() < deadline:
            last = kit.call_tool("get_deal", {"deal_id": deal_id})
            state = str(last.get("state") or "")
            if state in HIRE_SUCCESS_STATES or state in HIRE_DEAD_STATES:
                break
            if state and state != STATE_NEGOTIATING:
                stage = HIRE_STAGE_AGREED  # DEAL_AGREED / FUNDED: past negotiation
            time.sleep(poll_seconds)
    except KitError as exc:
        # The exception keeps its class (callers such as the canary route on
        # it); the CLI prints the left-behind deal beside the unchanged error.
        exc.context.update(_hire_left_deal(deal_id, stage))
        raise

    view = _deal_view(last)
    view["deal_id"] = deal_id
    view["request_id"] = request_ref
    if state in HIRE_SUCCESS_STATES:
        return view
    view["stage"] = stage
    if state in HIRE_DEAD_STATES:
        raise KitFailure(f"deal {deal_id} ended in {state}", view)
    raise KitFailure(
        f"timed out after {timeout_seconds:.0f}s waiting for the countersign;"
        f" check later with: python lhub.py status --deal {deal_id}",
        view,
    )


def do_result(
    kit: Kit,
    *,
    deal_id: str,
    out_path: Path,
    timeout_seconds: float,
    poll_seconds: float,
    write_out: Callable[[bytes], object] | None = None,
) -> dict[str, Any]:
    """Download the deliverable and verify it against the provider's proof hash (D-4).

    The verified bytes go to ``out_path`` as given (the CLI's ``result --out``,
    unconfined) unless ``write_out`` is passed: the MCP ``get_result`` tool
    passes its confined writer, which re-checks the destination right before
    the write (add-claude-code-plugin D-1). ``out`` in the result is
    ``out_path`` either way.
    """
    kit.ensure_session()
    deadline = time.monotonic() + timeout_seconds
    deal = kit.call_tool("get_deal", {"deal_id": deal_id})
    proof = deal.get("proof")
    while not isinstance(proof, dict):
        state = str(deal.get("state") or "")
        if state in ("CANCELLED", "REFUNDED", "SPLIT"):
            raise KitFailure(
                f"deal {deal_id} is {state}; no deliverable will arrive", _deal_view(deal)
            )
        if time.monotonic() >= deadline:
            raise KitFailure(
                f"no proof yet on deal {deal_id} after {timeout_seconds:.0f}s; the provider may"
                " still be working — re-run this command later",
                _deal_view(deal),
            )
        time.sleep(poll_seconds)
        deal = kit.call_tool("get_deal", {"deal_id": deal_id})
        proof = deal.get("proof")

    proof_hash = unfence(str(proof.get("hash") or ""))
    if _SHA256_FORM.fullmatch(proof_hash) is None:
        # sec S4-1: the unfenced hash serves only the strict comparison. A value
        # that fails the form check is provider-authored text, so it is never
        # echoed (this message can reach an LLM through `lhub.py mcp`); `status`
        # shows the proof as received, fenced by the bridge.
        raise KitError(
            "the proof's hash field is not a sha256 reference; cannot verify the"
            f" deliverable (see the proof as received: python lhub.py status --deal {deal_id})"
        )

    file_meta = kit.call_tool("download_deal_file", {"deal_id": deal_id, "kind": "deliverable"})
    content_b64 = file_meta.get("content_b64")
    if not isinstance(content_b64, str) or not content_b64:
        raise KitError("the deliverable has no downloadable content")
    try:
        data = base64.b64decode(content_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise KitError("the deliverable content_b64 is not valid base64") from exc

    matches, actual = verify_deliverable(proof_hash, data)
    state = str(deal.get("state") or "")
    if not matches:
        payload = {
            "deal_id": deal_id,
            "state": state,
            "delivered": False,
            "expected_sha256": proof_hash,
            "actual_sha256": actual,
            "next_step": (
                "hash mismatch — do not accept; you can open a dispute:"
                f' python lhub.py dispute --deal {deal_id} --reason "deliverable hash mismatch"'
            ),
        }
        raise KitFailure(
            f"deliverable hash mismatch on deal {deal_id}: proof says {proof_hash},"
            f" bytes are {actual} — not accepting; see `dispute`",
            payload,
        )

    if write_out is None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
    else:
        write_out(data)
    return {
        "deal_id": deal_id,
        "state": state,
        "delivered": True,
        "sha256": actual,
        "size": len(data),
        "out": str(out_path),
        # sec S4-1: provider-authored proof fields are emitted AS RECEIVED
        # (fenced by the bridge); only the hash is unfenced, and only for the
        # strictly-validated comparison above.
        "proof_method": str(proof.get("method") or ""),
        "next_step": f"review the deliverable; if it is good: python lhub.py accept --deal {deal_id}",
    }


def do_accept(kit: Kit, *, deal_id: str) -> dict[str, Any]:
    kit.ensure_session()
    out = kit.call_tool(
        "accept_deal", {"deal_id": deal_id, "idempotency_key": f"lhub-kit:accept:{deal_id}"}
    )
    # D-17: a one-line buyer→seller hint on stderr after a successful accept.
    # Informational, not imperative (P7); suppressible; stdout JSON unchanged.
    if os.environ.get("LHUB_KIT_QUIET") != "1":
        note(
            "Your agent can also sell services here: `lhub.py sell --help`, guide at /docs/sell.md"
        )
    view = _deal_view(out)
    view.setdefault("deal_id", deal_id)
    return view


def do_dispute(kit: Kit, *, deal_id: str, reason: str) -> dict[str, Any]:
    kit.ensure_session()
    out = kit.call_tool(
        "dispute_deal",
        {
            "deal_id": deal_id,
            "reason": reason,
            "idempotency_key": f"lhub-kit:dispute:{deal_id}",
        },
    )
    view = _deal_view(out)
    view.setdefault("deal_id", deal_id)
    return view


def do_find(kit: Kit, *, category: str, free_text: str, limit: int) -> dict[str, Any]:
    # D-9: search over the authenticated session when an identity exists, so
    # results carry provider liveness. A fresh caller with no key searches
    # anonymously — `find` alone never mints an identity.
    with_session = kit.key_path.exists()
    if with_session:
        kit.ensure_session()
    args: dict[str, Any] = {}
    if category:
        args["category"] = category
    if free_text:
        args["free_text"] = free_text
    if limit > 0:
        args["limit"] = limit
    return kit.call_tool("search_services", args, with_session=with_session)


def do_balance(kit: Kit) -> dict[str, Any]:
    kit.ensure_session()
    return kit.call_tool("get_balance", {})


def do_status(kit: Kit, *, deal_id: str) -> dict[str, Any]:
    kit.ensure_session()
    deal = kit.call_tool("get_deal", {"deal_id": deal_id})
    view = dict(deal)
    view.update(_deal_view(deal))
    return view


# ---------------------------------------------------------------------------
# Seller flows (seller-door D-10). The bridge tool contract is pinned by
# seller-door D-3/D-8 (D-14): create_listing / activate_listing /
# retire_listing / list_my_listings / get_inbox.
# ---------------------------------------------------------------------------


def build_listing_core(
    *,
    own_did: str,
    endpoint: str,
    category: str,
    title: str,
    summary: str,
    price: str,
    unit: str,
    model: str = "per_unit",
    min_charge: str = "",
    input_desc: str = "",
    input_types: str = "",
    deliverable_desc: str = "",
    deliverable_type: str = "",
    turnaround_hours: int = 24,
) -> dict[str, Any]:
    """Build a listing core LOCALLY from flags (D-10: the kit signs only bytes it built).

    The flags path authors the generic-task extension (seller-door D-1); the
    code-review leaf keeps its own richer extension, which these flags cannot
    truthfully fill — use ``--from`` with a complete core for it.
    """
    for name, value in (("--category", category), ("--title", title), ("--summary", summary)):
        if not value.strip():
            raise KitError(f"sell needs {name} (or --from with a complete core)")
    if category == CODE_REVIEW_CATEGORY:
        raise KitError(
            f"the {CODE_REVIEW_CATEGORY} leaf uses the code-review extension, whose fields"
            " (languages, scope, max_loc, ...) these flags cannot fill — pass a complete"
            " core with --from instead (worked example: /docs/sell.md)"
        )
    if not 1 <= turnaround_hours <= 168:
        raise KitError("--turnaround-hours must be between 1 and 168")
    price_minor = parse_amount_minor(price)
    media_types = [item.strip() for item in input_types.split(",") if item.strip()]
    extension: dict[str, Any] = {
        "input_description": (input_desc.strip() or f"One input file for: {summary.strip()}")[:500],
        "input_media_types": media_types or ["text/plain"],
        "deliverable_description": (
            deliverable_desc.strip() or f"The produced output for: {summary.strip()}"
        )[:500],
        "deliverable_media_type": deliverable_type.strip() or "text/plain",
        "turnaround_hours": turnaround_hours,
        # The kit enforces the OQ-2 cap on inputs it serves; declare it.
        "max_input_bytes": DELIVERABLE_CAP_BYTES,
    }
    pricing: dict[str, Any] = {
        "model": model,
        "currency": SETTLEMENT_UNIT,  # REG-1: pinned; `sell` never authors another currency
        "amount": render_decimal(price_minor),
        "unit": unit,
    }
    if min_charge.strip():
        pricing["min_charge"] = render_decimal(parse_amount_minor(min_charge))
    return {
        "schema_version": "0.1",
        "identity": {"agent_did": own_did, "display_name": title.strip()[:200]},
        "capability": {
            "category": category.strip(),
            "summary": summary.strip()[:1000],
            "extension_input": extension,
        },
        "pricing": pricing,
        "fulfillment": {
            "tier": 0,
            "proof": {
                "method": "signed_output",
                "hash_algorithm": "sha-256",
                "signature_alg": "ES256",
            },
        },
        "interface_bindings": [{"protocol": "mcp", "endpoint": endpoint}],
        "terms": {"service_terms_version": "1"},
    }


def validate_sell_core(core: dict[str, Any], *, own_did: str) -> tuple[bytes, str]:
    """Validate a core before signing; returns ``(canonical_bytes, content_hash)``.

    The pinned refusals (D-10): any currency other than LHUB-DEV (REG-1),
    ``min_charge < price``, a ``pricing.unit`` outside the identifier form.
    The registry independently re-validates everything against the schema
    (SEC-1 — these are conveniences that keep you from signing something the
    platform would refuse).
    """
    if not isinstance(core.get("identity"), dict):
        raise KitRefusal("refusing to sign listing: core has no identity object")
    identity = core["identity"]
    agent_did = identity.get("agent_did")
    if agent_did in (None, ""):
        identity["agent_did"] = own_did
    elif agent_did != own_did:
        raise KitRefusal(
            f"refusing to sign listing: identity.agent_did {agent_did!r} is not this kit's DID"
            f" ({own_did}) — a listing is signed by its own provider (F4-5)"
        )
    if "provider_signature" in core:
        note("note: replacing the provider_signature carried by the input core with our own")
        core.pop("provider_signature")

    missing = [
        key
        for key in (
            "schema_version",
            "identity",
            "capability",
            "pricing",
            "fulfillment",
            "interface_bindings",
            "terms",
        )
        if key not in core
    ]
    if missing:
        raise KitRefusal(f"refusing to sign listing: core is missing {missing}")
    if core.get("schema_version") != "0.1":
        raise KitRefusal('refusing to sign listing: schema_version must be "0.1"')

    pricing = core.get("pricing")
    if not isinstance(pricing, dict):
        raise KitRefusal("refusing to sign listing: core has no pricing object")
    if pricing.get("currency") != SETTLEMENT_UNIT:
        raise KitRefusal(
            f"refusing to sign listing: pricing.currency {pricing.get('currency')!r} is not"
            f" {SETTLEMENT_UNIT!r} (REG-1: the sandbox settles dev currency only)"
        )
    if pricing.get("model") not in ("per_unit", "flat"):
        raise KitRefusal("refusing to sign listing: pricing.model must be per_unit or flat")
    unit = pricing.get("unit")
    if not isinstance(unit, str) or _UNIT_ID_FORM.fullmatch(unit) is None:
        raise KitRefusal("refusing to sign listing: pricing.unit must match [A-Za-z0-9_.-]{1,32}")
    amount_raw = pricing.get("amount")
    if not isinstance(amount_raw, str) or _DECIMAL_AMOUNT_FORM.fullmatch(amount_raw) is None:
        raise KitRefusal(
            'refusing to sign listing: pricing.amount must be a decimal string like "0.05"'
        )
    price_minor = parse_amount_minor(amount_raw)
    if price_minor < 1:
        raise KitRefusal(
            "refusing to sign listing: the price is zero — no proposal could ever match it"
            " (amounts must be at least 1 minor unit)"
        )
    raw_min = pricing.get("min_charge")
    if raw_min is not None:
        if not isinstance(raw_min, str) or _DECIMAL_AMOUNT_FORM.fullmatch(raw_min) is None:
            raise KitRefusal(
                "refusing to sign listing: pricing.min_charge must be a decimal string"
            )
        if parse_amount_minor(raw_min) < price_minor:
            raise KitRefusal(
                "refusing to sign listing: min_charge is below the unit price — the bridge"
                " can never derive such an amount, so no proposal would match (D-10)"
            )
    capability = core.get("capability")
    if not isinstance(capability, dict) or not str(capability.get("category") or "").strip():
        raise KitRefusal("refusing to sign listing: capability.category is required")

    canonical = jcs_canonicalize(core)
    return canonical, hashlib.sha256(canonical).hexdigest()


def _search_check(kit: Kit, *, listing_id: str, category: str) -> str:
    """Look for a just-activated listing in search (indexing is publish-after-commit).

    A search hit carries the listing's id as ``listing.id`` (discovery's
    search result; the bridge copies it unfenced). The check spends at most
    ``len(SEARCH_CHECK_WAITS_SECONDS)`` searches, waiting before each, because
    the anonymous-read budget is shared per source (anon_read, 120/min) — task
    3.2. A category with more ACTIVE listings than the page limit can still
    hide a new listing from a no-text search (R-HPS-7); that reads as
    ``not_yet_indexed``, never as a failure of the sell.
    """
    wanted = listing_id.lower()
    for wait in SEARCH_CHECK_WAITS_SECONDS:
        time.sleep(wait)
        try:
            found = kit.call_tool(
                "search_services", {"category": category, "limit": 50}, with_session=True
            )
        except KitError as exc:
            note(f"search check unavailable: {exc}")
            return "search_unavailable"
        results = found.get("results")
        if isinstance(results, list):
            for hit in results:
                listing = hit.get("listing") if isinstance(hit, dict) else None
                hit_id = listing.get("id") if isinstance(listing, dict) else None
                if isinstance(hit_id, str) and hit_id.lower() == wanted:
                    return "found"
    return "not_yet_indexed"


def do_sell(kit: Kit, core: dict[str, Any]) -> dict[str, Any]:
    """Create + activate a listing: sign locally, relay, UUID-check, activate, store.

    Registry-bound idempotency keys are 128-bit random (a global namespace)
    and stored with the pending operation, so a retry of the SAME core replays
    the same keys (D-10).
    """
    kit.ensure_session()
    canonical, content_hash = validate_sell_core(core, own_did=kit.did)
    pending_name = f"create-{content_hash}"
    pending = kit.load_pending(pending_name) or {}
    create_key = str(pending.get("create_key") or secrets.token_hex(16))
    activate_key = str(pending.get("activate_key") or secrets.token_hex(16))
    kit.save_pending(
        pending_name,
        {"create_key": create_key, "activate_key": activate_key, "content_hash": content_hash},
    )

    jws = sign_es256(kit.ensure_key(), canonical, kid=kit.did)
    signed_core = dict(core)
    signed_core["provider_signature"] = jws

    created = kit.call_tool("create_listing", {"core": signed_core, "idempotency_key": create_key})
    listing_id = unfence(str(created.get("listing_id") or ""))
    if _UUID_FORM.fullmatch(listing_id) is None:
        raise KitError(
            f"create_listing returned a non-UUID listing_id {listing_id!r}; not activating"
        )
    listing_id = listing_id.lower()
    returned_hash = unfence(str(created.get("content_hash") or ""))
    if returned_hash and returned_hash != content_hash:
        raise KitError(
            "the registry's content hash disagrees with our own canonicalization"
            f" (ours {content_hash}, registry {returned_hash}); not activating —"
            " countersigning against this listing could never match"
        )

    # Activate action built LOCALLY and signed over our own bytes (never a
    # server-returned object — F4-4 / sec R1 N-4).
    action = {"actor_did": kit.did, "action": "activate", "listing_id": listing_id}
    action_jws = sign_es256(kit.ensure_key(), jcs_canonicalize(action), kid=kit.did)
    activated = kit.call_tool(
        "activate_listing",
        {"action": {**action, "signature": action_jws}, "idempotency_key": activate_key},
    )

    stored_path = kit.store_listing(listing_id, content_hash, signed_core)
    kit.clear_pending(pending_name)
    category = str(core.get("capability", {}).get("category") or "")
    search_check = _search_check(kit, listing_id=listing_id, category=category)
    return {
        "listing_id": listing_id,
        "status": unfence(str(activated.get("status") or "")) or "active",
        "content_hash": content_hash,
        "search_check": search_check,
        "stored": str(stored_path),
        "next_step": "poll for orders: python lhub.py inbox (or run: python lhub.py serve)",
    }


def do_listings(kit: Kit) -> dict[str, Any]:
    kit.ensure_session()
    return kit.call_tool("list_my_listings", {})


def do_retire(kit: Kit, *, listing_id: str) -> dict[str, Any]:
    safe_id = require_uuid(listing_id, what="listing id")
    kit.ensure_session()
    pending_name = f"retire-{safe_id}"
    pending = kit.load_pending(pending_name) or {}
    retire_key = str(pending.get("retire_key") or secrets.token_hex(16))
    kit.save_pending(pending_name, {"retire_key": retire_key})
    action = {"actor_did": kit.did, "action": "retire", "listing_id": safe_id}
    action_jws = sign_es256(kit.ensure_key(), jcs_canonicalize(action), kid=kit.did)
    out = kit.call_tool(
        "retire_listing",
        {"action": {**action, "signature": action_jws}, "idempotency_key": retire_key},
    )
    kit.clear_pending(pending_name)
    view = dict(out)
    view.setdefault("listing_id", safe_id)
    return view


def _inbox_items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The inbox item list under the PINNED wrapper key ``items`` (D-14).

    The bridge contract pins the wrapper key to ``items``; the earlier
    tolerant fallbacks (``results``/``inbox``) are removed per D-14 ("the
    kit's tolerant fallbacks for other wrapper keys are removed once Slice 3
    lands"). A payload without an ``items`` list is a CONTRACT error surfaced
    legibly — never silently treated as an empty inbox.
    """
    raw = payload.get("items")
    if not isinstance(raw, list):
        raise KitError(
            "get_inbox returned no 'items' list (the D-14 pinned wrapper key);"
            f" got keys {sorted(str(key) for key in payload)} — bridge/kit contract mismatch"
        )
    return [item for item in raw if isinstance(item, dict)]


def countersign_item(kit: Kit, item: Mapping[str, Any], *, now_unix: float) -> dict[str, Any]:
    """Run ALL seller checks for one `countersign` inbox item; sign only if every one passes.

    Any check failure is recorded against the proposal sha and NEVER retried
    for that sha; the signature — when it happens — is over the kit's OWN
    canonicalization of the content it validated (compare-then-sign).
    """
    deal_id = require_uuid(str(item.get("deal_id") or ""))

    # (1) The deal as the platform records it — the authoritative comparison source.
    deal_raw = kit.call_tool("get_deal", {"deal_id": deal_id})
    deal = normalize_deal_record(deal_raw)
    if deal["state"] != STATE_NEGOTIATING:
        return {"action": "skipped", "reason": f"deal state {deal['state']}; nothing to sign"}

    # The one-shot proposal file (its sha keys the refusal memory).
    file_meta = kit.call_tool(
        "download_deal_file", {"deal_id": deal_id, "kind": "agreement_proposal"}
    )
    content_b64 = file_meta.get("content_b64")
    if not isinstance(content_b64, str) or not content_b64:
        raise KitError("the agreement proposal has no downloadable content")
    try:
        data = base64.b64decode(content_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise KitError("the agreement proposal content_b64 is not valid base64") from exc
    proposal_sha = hashlib.sha256(data).hexdigest()

    prior = kit.refusal_reason(deal_id, proposal_sha)
    if prior is not None:
        # The stored reason was clipped at record time, but a pre-clip or
        # tampered entry must stay bounded printable ASCII on re-emission too.
        return {
            "action": "skipped",
            "reason": f"previously refused (same proposal sha, not retried): {_ascii_clip(prior)}",
        }

    # D-4a: ownership is matched by the deal's pinned listing_content_hash —
    # escrow deals carry no listing UUID. The AUTHORITATIVE hash is the deal
    # record's, never the inbox item's copy.
    pinned_hash = deal.get("listing_content_hash")
    stored = kit.find_listing_by_hash(pinned_hash) if isinstance(pinned_hash, str) else None
    try:
        # (4) Strict envelope parse; (2+3) binding; (5) freshness; (6) signer +
        # signature over OUR canonicalization; (7) content == deal record;
        # (8) price terms from the STORED core.
        parsed = parse_seller_proposal(data)
        check_seller_binding(
            own_did=kit.did,
            deal=deal,
            stored=stored,
            input_present=isinstance(item.get("input"), dict),
        )
        check_proposal_freshness(parsed.issued_at_unix, now_unix=now_unix)
        if parsed.signer != deal["buyer_did"]:
            raise KitRefusal(
                "refusing to countersign: the proposal's signer is not the deal's buyer"
            )
        canonical = jcs_canonicalize(parsed.content)
        try:
            verify_jws_es256_canonical(
                did=parsed.signer, jws=parsed.jws, expected_canonical=canonical
            )
        except KitRefusal:
            raise
        except KitError as exc:
            raise KitRefusal(f"refusing to countersign: buyer signature invalid: {exc}") from exc
        check_content_matches_deal(content=parsed.content, deal=deal, own_did=kit.did)
        if stored is None:  # unreachable: check_seller_binding refused the None case
            raise KitRefusal("refusing to countersign: listing is not in the listings store")
        core = stored.get("core")
        pricing = core.get("pricing") if isinstance(core, dict) else None
        if not isinstance(pricing, dict):
            raise KitRefusal("refusing to countersign: stored listing core carries no pricing")
        check_price_terms(
            amount=int(parsed.content["amount"]),
            pricing=pricing,
            proposal_unit=str(parsed.content["unit"]),
        )
    except KitRefusal as exc:
        kit.record_refusal(deal_id, proposal_sha, str(exc))
        note(f"deal {deal_id}: {exc}")
        return {"action": "refused", "reason": str(exc), "proposal_sha256": proposal_sha}
    except Exception as exc:
        # Fail-safe (sec B-1): counterparty-controlled bytes must only ever
        # REFUSE, never kill the poll loop. Everything in the block above is
        # derived from the downloaded proposal (the deal record and the stored
        # listing were already strict-parsed), so an unexpected exception here
        # is content-caused and deterministic for these bytes: record it
        # against the proposal sha exactly like a refusal — never re-evaluated
        # each poll — and return. NOTHING was signed (the sign call sits below
        # this block). Mirrors the house agent countersign.py posture: a
        # latent bug must not pin the loop.
        reason = "refusing to countersign (fail-safe): " + _fail_safe_reason(exc)
        kit.record_refusal(deal_id, proposal_sha, reason)
        note(f"deal {deal_id}: {reason}")
        return {"action": "refused", "reason": reason, "proposal_sha256": proposal_sha}

    # (9) Compare-then-sign over content we hold: sign OUR canonical bytes and
    # assemble the two-signature artifact (sorted by signer DID, the dualsig
    # normalisation), then agree as the provider — the last signer (SM-3).
    our_jws = sign_es256(kit.ensure_key(), canonical, kid=kit.did)
    ordered = sorted(
        [{"signer": parsed.signer, "jws": parsed.jws}, {"signer": kit.did, "jws": our_jws}],
        key=lambda sig: sig["signer"],
    )
    signatures_json = json.dumps(ordered, separators=(",", ":")).encode("ascii")
    artifact = b'{"content":' + canonical + b',"signatures":' + signatures_json + b"}"
    idempotency_key = hashlib.sha256((deal_id + proposal_sha).encode("ascii")).hexdigest()
    agreed = kit.call_tool(
        "agree_deal",
        {
            "deal_id": deal_id,
            "idempotency_key": idempotency_key,
            "signed_artifact": base64.b64encode(artifact).decode("ascii"),
        },
    )
    return {
        "action": "countersigned",
        "state": agreed.get("state"),
        "proposal_sha256": proposal_sha,
    }


def write_job_input(job_dir: Path, data: bytes) -> Path:
    """Write verified input bytes to ``<job_dir>/input`` (O_EXCL|O_NOFOLLOW, idempotent).

    Mirrors the house agent's jobdir discipline: a temp node created
    exclusively with no-follow, then an atomic replace; a pre-existing symlink
    at any touched node is refused; an already-present input is left alone.
    """
    target = job_dir / "input"
    if target.is_symlink():
        raise KitError(f"refusing to write through a pre-existing symlink: {target}")
    if target.exists():
        return target
    tmp = job_dir / "input.tmp"
    tmp.unlink(missing_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    tmp.replace(target)
    return target


def fetch_job_input(kit: Kit, item: Mapping[str, Any]) -> dict[str, Any]:
    """Fetch a funded job's input: download, verify sha == request_id, THEN place."""
    deal_id = require_uuid(str(item.get("deal_id") or ""))
    job_dir = kit.job_dir(deal_id)
    target = job_dir / "input"
    if target.is_symlink():
        raise KitError(f"refusing to use a pre-existing symlink: {target}")
    if target.exists():
        return {"action": "input_present", "path": str(target)}

    deal = normalize_deal_record(kit.call_tool("get_deal", {"deal_id": deal_id}))
    request_id = str(deal["request_id"])
    if _SHA256_FORM.fullmatch(request_id) is None:
        return {"action": "input_refused", "reason": "deal request_id is not sha256-bound"}
    file_meta = kit.call_tool("download_deal_file", {"deal_id": deal_id, "kind": "job_input"})
    content_b64 = file_meta.get("content_b64")
    if not isinstance(content_b64, str) or not content_b64:
        return {"action": "input_refused", "reason": "job_input has no downloadable content"}
    try:
        data = base64.b64decode(content_b64, validate=True)
    except (ValueError, TypeError):
        return {"action": "input_refused", "reason": "job_input content_b64 is not valid base64"}
    actual = sha256_ref(data)
    if actual != request_id:
        # Never place unverified bytes (SEC-2; the input SHALL be written only
        # when its SHA-256 equals the deal's request_id).
        return {
            "action": "input_refused",
            "reason": f"job_input hash {actual} != deal request_id {request_id}",
        }
    path = write_job_input(job_dir, data)
    return {"action": "input_fetched", "path": str(path), "sha256": actual, "size": len(data)}


def _error_fields(exc: KitError) -> dict[str, Any]:
    """The machine-readable fields of a failure: its reason, plus the D-4 code
    and ``retryable: true`` when the marketplace refused for now."""
    fields: dict[str, Any] = {"reason": str(exc)}
    if isinstance(exc, KitRetryableError):
        fields["code"] = exc.code
        fields["retryable"] = True
    return fields


def do_inbox(kit: Kit, *, countersign: bool = True) -> dict[str, Any]:
    """One poll of the seller inbox: countersign matches, fetch funded inputs (D-10)."""
    kit.ensure_session()
    payload = kit.call_tool("get_inbox", {})
    items = _inbox_items(payload)
    actions: list[dict[str, Any]] = []
    now_unix = time.time()
    for item in items:
        todo = unfence(str(item.get("todo") or ""))
        deal_ref = str(item.get("deal_id") or "")
        try:
            if todo == "countersign" and countersign:
                actions.append(
                    {"deal_id": deal_ref, **countersign_item(kit, item, now_unix=now_unix)}
                )
            elif todo == "fulfil":
                actions.append({"deal_id": deal_ref, **fetch_job_input(kit, item)})
        except KitError as exc:
            # A transport/tool failure is NOT a check refusal: it is reported
            # and the item is retried on the next poll. A retryable refusal
            # (D-4) also carries its code, so an outage reads as one.
            actions.append({"deal_id": deal_ref, "action": "error", **_error_fields(exc)})
        except Exception as exc:
            # Fail-safe (sec B-1): ONE bad item must never kill the poll —
            # the remaining items (a funded fulfil job included) still
            # process. Content-derived failures were already recorded against
            # their proposal sha inside countersign_item; what reaches this
            # boundary is not attributable to proposal bytes, so it is NOT
            # memorized and the item is retried on the next poll.
            actions.append(
                {"deal_id": deal_ref, "action": "error", "reason": _fail_safe_reason(exc)}
            )
    return {
        "polled_at": payload.get("polled_at"),
        "poll_hint_seconds": payload.get("poll_hint_seconds"),
        "items": items,
        "actions": actions,
    }


def do_deliver(kit: Kit, *, deal_id: str, data: bytes) -> dict[str, Any]:
    """Upload the deliverable, then submit the Tier-0 proof (deterministic keys).

    The proof is the platform's Tier-0 runtime shape, ported from the house
    agent (signing.py): ``{method: "signed-output-hash", hash: "sha256:<hex>",
    jws}`` where the JWS is our ES256 over the JCS of ``{hash, deal_id,
    issued_at}``.
    """
    safe_id = require_uuid(deal_id)
    if len(data) > DELIVERABLE_CAP_BYTES:
        raise KitError(
            f"deliverable is {len(data)} bytes; the deal-file cap is"
            f" {DELIVERABLE_CAP_BYTES} (160 KiB)"
        )
    if not data:
        raise KitError("deliverable is empty; refusing to submit an empty proof")
    kit.ensure_session()
    proof_hash = sha256_ref(data)
    uploaded = kit.call_tool(
        "upload_deal_file",
        {
            "deal_id": safe_id,
            "kind": "deliverable",
            "content_b64": base64.b64encode(data).decode("ascii"),
        },
    )
    uploaded_sha = unfence(str(uploaded.get("sha256") or ""))
    if uploaded_sha and uploaded_sha not in (proof_hash, proof_hash.removeprefix("sha256:")):
        raise KitError(
            f"deliverable upload came back with hash {uploaded_sha!r}, expected {proof_hash!r}"
        )
    issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    jws = kit.sign_payload({"hash": proof_hash, "deal_id": safe_id, "issued_at": issued_at})
    out = kit.call_tool(
        "submit_proof",
        {
            "deal_id": safe_id,
            "proof_payload": {
                "method": PROOF_METHOD_SIGNED_OUTPUT_HASH,
                "hash": proof_hash,
                "jws": jws,
            },
            # Deterministic: a replay of the SAME deliverable for the SAME deal
            # derives the SAME key (SM-5 / SEC-4; the house agent's discipline).
            "idempotency_key": f"lhub-kit:proof:{safe_id}:{proof_hash}",
        },
    )
    return {
        "deal_id": safe_id,
        "state": out.get("state"),
        "sha256": proof_hash,
        "size": len(data),
        "proof_method": PROOF_METHOD_SIGNED_OUTPUT_HASH,
        "next_step": "the buyer verifies and accepts; funds release on accept (or accept-TTL)",
    }


# ---------------------------------------------------------------------------
# serve --exec (seller-door D-10): run the seller's own command per funded job.
# ---------------------------------------------------------------------------


class ExecOutcome(NamedTuple):
    """What happened to one ``serve --exec`` child process."""

    status: str  # "ok" | "exit" | "timeout" | "oversize" | "spawn_failed"
    stdout: bytes
    exit_code: int | None
    detail: str
    stderr_tail: str


def _kill_process_group(proc: subprocess.Popen[bytes]) -> None:
    """SIGKILL the child's whole process group (start_new_session made pid == pgid)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # already gone / foreign pgid
        proc.kill()
    proc.wait()


def run_exec_command(
    argv_base: list[str],
    *,
    input_path: Path,
    job_dir: Path,
    timeout_seconds: float,
    stdout_cap: int = DELIVERABLE_CAP_BYTES,
) -> ExecOutcome:
    """Run the seller's command for one job, hardened per D-10.

    - no shell: ``argv_base`` came from ``shlex.split``; the input path is the
      LAST argv entry (untrusted data as a path argument, never interpolated);
    - minimal environment: ``PATH``, ``LHUB_JOB_DIR``, ``LANG`` — never the
      kit's home or key path;
    - stdout is read incrementally and the child is KILLED past ``stdout_cap``
      (output is never buffered unbounded);
    - on timeout the whole process group is killed.
    """
    argv = [*argv_base, str(input_path)]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LHUB_JOB_DIR": str(job_dir),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    try:
        # S603: deliberately no shell; argv is the seller's OWN configured command.
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=str(job_dir),
            start_new_session=True,
        )
    except OSError as exc:
        # sec N-2: a missing or non-executable --exec command must not kill
        # the serve loop — it is a per-job failure like any other (the caller
        # records failed.json and the job stays queued for a human).
        return ExecOutcome(
            status="spawn_failed",
            stdout=b"",
            exit_code=None,
            detail=f"command could not be started: {exc}",
            stderr_tail="",
        )
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE guarantees both
        _kill_process_group(proc)
        raise KitError("could not attach to the exec command's output")

    deadline = time.monotonic() + timeout_seconds
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    status = "ok"
    sel = selectors.DefaultSelector()
    for stream, tag in ((proc.stdout, "out"), (proc.stderr, "err")):
        os.set_blocking(stream.fileno(), False)
        sel.register(stream.fileno(), selectors.EVENT_READ, data=tag)
    try:
        while sel.get_map() and status == "ok":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            for key, _events in sel.select(timeout=min(remaining, 0.25)):
                try:
                    chunk = os.read(key.fd, 65536)
                except (BlockingIOError, OSError):
                    continue
                if not chunk:
                    sel.unregister(key.fd)
                    continue
                if key.data == "out":
                    stdout_buf += chunk
                    if len(stdout_buf) > stdout_cap:
                        status = "oversize"
                        break
                elif len(stderr_buf) < SERVE_STDERR_CAP_BYTES:
                    stderr_buf += chunk[: SERVE_STDERR_CAP_BYTES - len(stderr_buf)]
    finally:
        sel.close()

    exit_code: int | None = None
    if status == "ok":
        try:
            exit_code = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            status = "timeout"
    if status != "ok":
        _kill_process_group(proc)
    proc.stdout.close()
    proc.stderr.close()
    if status == "ok" and exit_code != 0:
        status = "exit"

    stderr_tail = stderr_buf.decode("utf-8", errors="replace")[-1000:]
    detail = {
        "ok": "",
        "exit": f"command exited with code {exit_code}",
        "timeout": f"command killed after {timeout_seconds:.0f}s (process group)",
        "oversize": f"command killed: stdout exceeded the {stdout_cap} byte deliverable cap",
    }[status]
    return ExecOutcome(
        status=status,
        stdout=bytes(stdout_buf),
        exit_code=exit_code,
        detail=detail,
        stderr_tail=stderr_tail,
    )


def _job_timeout_seconds(kit: Kit, listing_content_hash: str) -> float:
    """The per-job timeout: the stored listing's turnaround, hard-capped at 30 min.

    The listing is resolved by its content hash (D-4a: deals carry no listing
    UUID); an unknown hash falls back to the cap.
    """
    stored = kit.find_listing_by_hash(listing_content_hash)
    if stored is not None:
        core = stored.get("core")
        capability = core.get("capability") if isinstance(core, dict) else None
        extension = capability.get("extension_input") if isinstance(capability, dict) else None
        hours = extension.get("turnaround_hours") if isinstance(extension, dict) else None
        if isinstance(hours, int) and not isinstance(hours, bool) and hours >= 1:
            return float(min(hours * 3600, SERVE_TIMEOUT_CAP_SECONDS))
    return float(SERVE_TIMEOUT_CAP_SECONDS)


def run_serve_job(kit: Kit, item: Mapping[str, Any], argv_base: list[str]) -> dict[str, Any]:
    """Run the configured command for one funded job and deliver on exit 0.

    A failed or timed-out command records the failure and leaves the job for a
    human; a job that already has a proof (or a local delivered marker) is
    never delivered again.
    """
    deal_id = require_uuid(str(item.get("deal_id") or ""))
    job_dir = kit.job_dir(deal_id)
    input_path = job_dir / "input"
    if (job_dir / "delivered.json").exists():
        return {"deal_id": deal_id, "action": "already_delivered"}
    if isinstance(item.get("deliverable"), dict):
        # The platform already holds a deliverable for this deal; never re-run.
        return {"deal_id": deal_id, "action": "already_delivered", "reason": "deliverable on deal"}
    if (job_dir / "failed.json").exists():
        return {
            "deal_id": deal_id,
            "action": "failed_previously",
            "reason": "see failed.json; remove it to retry by hand",
        }
    if not input_path.exists():
        return {"deal_id": deal_id, "action": "waiting_input"}

    try:
        timeout = _job_timeout_seconds(kit, str(item.get("listing_content_hash") or ""))
        outcome = run_exec_command(
            argv_base, input_path=input_path, job_dir=job_dir, timeout_seconds=timeout
        )
        now_z = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if outcome.status != "ok":
            kit.write_job_marker(
                job_dir / "failed.json",
                {
                    "status": outcome.status,
                    "exit_code": outcome.exit_code,
                    "detail": outcome.detail,
                    "stderr_tail": outcome.stderr_tail,
                    "ts": now_z,
                },
            )
            note(f"deal {deal_id}: {outcome.detail}; job left for a human")
            return {
                "deal_id": deal_id,
                "action": "exec_failed",
                "status": outcome.status,
                "detail": outcome.detail,
            }
        try:
            delivered = do_deliver(kit, deal_id=deal_id, data=outcome.stdout)
        except KitError as exc:
            # A transport failure or a retryable refusal parks the job here
            # exactly as before (D-4: a retryable refusal is handled like a
            # transport error); the record now carries the code, so a human
            # can tell an outage from a refusal before retrying by hand.
            fields = _error_fields(exc)
            marker: dict[str, Any] = {"status": "deliver_failed", "detail": str(exc), "ts": now_z}
            marker.update({key: value for key, value in fields.items() if key != "reason"})
            kit.write_job_marker(job_dir / "failed.json", marker)
            note(f"deal {deal_id}: deliver failed: {exc}; job left for a human")
            return {"deal_id": deal_id, "action": "deliver_failed", **fields}
        kit.write_job_marker(
            job_dir / "delivered.json",
            {"sha256": delivered.get("sha256"), "state": delivered.get("state"), "ts": now_z},
        )
        return {"deal_id": deal_id, "action": "delivered", **delivered}
    except KitError:
        raise  # legible per-job failure; do_serve_round records it and moves on
    except Exception as exc:
        # Fail-safe (sec B-1/N-2 class): an unexpected failure in the
        # exec/deliver path records the job as failed and keeps the serve
        # loop alive. The marker write is itself best-effort — the loop
        # survives even a failing disk (the job then retries next round).
        reason = _fail_safe_reason(exc)
        with contextlib.suppress(OSError):
            kit.write_job_marker(
                job_dir / "failed.json",
                {
                    "status": "unexpected",
                    "detail": reason,
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
            )
        note(f"deal {deal_id}: serve job failed unexpectedly: {reason}; job left for a human")
        return {"deal_id": deal_id, "action": "error", "status": "unexpected", "reason": reason}


def do_serve_round(kit: Kit, *, argv_base: list[str] | None) -> dict[str, Any]:
    """One serve round: poll the inbox (countersign + input fetch), then run jobs."""
    summary = do_inbox(kit, countersign=True)
    jobs: list[dict[str, Any]] = []
    if argv_base is not None:
        for item in summary["items"]:
            if unfence(str(item.get("todo") or "")) != "fulfil":
                continue
            try:
                jobs.append(run_serve_job(kit, item, argv_base))
            except KitError as exc:
                jobs.append(
                    {
                        "deal_id": str(item.get("deal_id") or ""),
                        "action": "error",
                        **_error_fields(exc),
                    }
                )
            except Exception as exc:
                # Fail-safe (sec B-1): one job must never kill the serve
                # loop — record the outcome, keep the remaining jobs moving.
                jobs.append(
                    {
                        "deal_id": str(item.get("deal_id") or ""),
                        "action": "error",
                        "reason": _fail_safe_reason(exc),
                    }
                )
    todo_counts: dict[str, int] = {}
    for item in summary["items"]:
        todo = unfence(str(item.get("todo") or "")) or "unknown"
        todo_counts[todo] = todo_counts.get(todo, 0) + 1
    return {
        "polled_at": summary.get("polled_at"),
        "todo_counts": todo_counts,
        "actions": summary["actions"],
        "jobs": jobs,
    }


def run_serve_loop(
    kit: Kit, *, argv_base: list[str] | None, interval_seconds: float, once: bool
) -> int:
    """The serve loop: poll rounds forever, SURVIVING marketplace outages.

    A seller loop that dies on a bridge restart becomes an offline listing,
    so a TRANSPORT failure (:class:`KitTransportError`: network down, bridge
    restarting, 5xx, session churn) is logged in one line and retried with
    exponential backoff — ``interval x 2^n`` capped at
    ``SERVE_BACKOFF_CAP_SECONDS``, reset on the first successful round. A
    retryable refusal (:class:`KitRetryableError`, D-4: ``upstream_unavailable``
    or ``rate_limited``) is handled the same way. A rate-limited
    ``register_agent`` (the re-handshake re-registers) keeps doubling up to
    ``SERVE_IDENTITY_BACKOFF_CAP_SECONDS`` instead, since the identity limit's
    window lasts up to a day. Only a NON-retryable error (a tool refusal, or a
    contract error such as a ``get_inbox`` payload without ``items``) or
    Ctrl-C/SIGTERM ends the loop. With ``once=True`` the current semantics
    hold: any failure, transport included, exits non-zero after the single
    round.
    """
    round_no = 0
    transport_failures = 0
    while True:
        round_no += 1
        try:
            payload = do_serve_round(kit, argv_base=argv_base)
        except (KitTransportError, KitRetryableError) as exc:
            if once:
                raise
            transport_failures += 1
            # Clamp the exponent: int(2**n) past ~2^1023 no longer converts
            # to float and the multiply raises OverflowError — a days-long
            # outage must not crash the loop at failure ~1024 (sec R2 N-2).
            # 2^20 x any legal interval is already far beyond the cap.
            exponent = min(transport_failures - 1, 20)
            cap = SERVE_BACKOFF_CAP_SECONDS
            if isinstance(exc, KitRetryableError) and exc.identity_window:
                cap = SERVE_IDENTITY_BACKOFF_CAP_SECONDS
            delay = min(interval_seconds * (2**exponent), cap)
            if isinstance(exc, KitRetryableError):
                what = f"marketplace refused for now [{exc.code}]"
            else:
                what = "marketplace unreachable"
            note(
                f"serve round {round_no}: {what} ({exc});"
                f" retrying in {delay:.0f}s"
                f" (consecutive failures: {transport_failures})"
            )
            time.sleep(delay)
            continue
        transport_failures = 0
        payload["round"] = round_no
        emit(payload)
        if once:
            return 0
        time.sleep(interval_seconds)


# ---------------------------------------------------------------------------
# Commands.
# ---------------------------------------------------------------------------


def json_text(payload: Mapping[str, Any]) -> str:
    """The kit's one JSON rendering: stdout and MCP tool-error texts alike."""
    return json.dumps(payload, indent=2, sort_keys=False)


def emit(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(json_text(payload) + "\n")


def failure_payload(exc: KitError) -> dict[str, Any]:
    """The JSON object for one failure: what the CLI prints on stdout, and the text
    the MCP server gives the caller for the same failure. ONE helper, so the two
    surfaces cannot drift (D-4, orchestrator ruling 2026-11-16).

    A ``KitFailure`` is its payload plus ``error``. Any other failure is
    ``error``, then ``code`` and ``retryable`` for a retryable refusal, then the
    context a flow attached (a failed hire's ``deal_id``/``stage``/``next_step``),
    which never replaces the first three.
    """
    if isinstance(exc, KitFailure):
        payload = dict(exc.payload)
        payload["error"] = str(exc)
        return payload
    fields = _error_fields(exc)
    failure: dict[str, Any] = {"error": fields.pop("reason"), **fields}
    for key, value in exc.context.items():
        failure.setdefault(key, value)
    return failure


def cmd_init(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    kit.ensure_key()
    registration = kit.handshake()
    balance: dict[str, Any] | None = None
    try:
        balance = kit.call_tool("get_balance", {})
    except KitError as exc:
        note(f"balance unavailable: {exc}")
    emit(
        {
            "did": kit.did,
            "key_path": str(kit.key_path),
            "home": str(kit.home),
            "registration": registration,
            "balance": balance,
        }
    )
    return 0


def cmd_find(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    emit(do_find(kit, category=args.category, free_text=args.free_text, limit=args.limit))
    return 0


def cmd_hire(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    input_path = Path(args.input)
    try:
        input_bytes = input_path.read_bytes()
    except OSError as exc:
        raise KitError(f"cannot read the input file {input_path}: {exc}") from exc
    max_price_minor = parse_amount_minor(args.max_price)
    emit(
        do_hire(
            kit,
            listing_id=args.listing,
            input_bytes=input_bytes,
            max_price_minor=max_price_minor,
            pinned_provider=args.provider,
            quantity=args.quantity,
            timeout_seconds=args.timeout,
            poll_seconds=args.poll,
        )
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    emit(do_status(kit, deal_id=args.deal))
    return 0


def cmd_result(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    emit(
        do_result(
            kit,
            deal_id=args.deal,
            out_path=Path(args.out),
            timeout_seconds=args.timeout,
            poll_seconds=args.poll,
        )
    )
    return 0


def cmd_accept(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    emit(do_accept(kit, deal_id=args.deal))
    return 0


def cmd_dispute(args: argparse.Namespace) -> int:
    reason = args.reason.strip()
    if not reason:
        raise KitError("dispute needs a non-empty --reason")
    kit = Kit.from_env(args.url)
    emit(do_dispute(kit, deal_id=args.deal, reason=reason))
    return 0


def cmd_balance(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    emit(do_balance(kit))
    return 0


def _core_from_args(kit: Kit, args: argparse.Namespace) -> dict[str, Any]:
    """Build the core from flags, or load it from ``--from`` (never both)."""
    if args.from_file:
        if args.category or args.title or args.summary or args.price or args.unit:
            raise KitError("use either --from or the listing flags, not both")
        path = Path(args.from_file)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise KitError(f"cannot read {path}: {exc}") from exc
        try:
            core = json.loads(raw)
        except ValueError as exc:
            raise KitError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(core, dict):
            raise KitError(f"{path} must contain a JSON object (the listing core)")
        return core
    return build_listing_core(
        own_did=kit.did,
        endpoint=_redact_url(kit.base_url) + MCP_PATH,  # never publish userinfo
        category=args.category or "",
        title=args.title or "",
        summary=args.summary or "",
        price=args.price or "",
        unit=args.unit or "",
        model=args.model,
        min_charge=args.min_charge or "",
        input_desc=args.input_desc or "",
        input_types=args.input_types or "",
        deliverable_desc=args.deliverable_desc or "",
        deliverable_type=args.deliverable_type or "",
        turnaround_hours=args.turnaround_hours,
    )


def cmd_sell(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    kit.ensure_key()
    if not args.from_file:
        for name, value in (("--price", args.price), ("--unit", args.unit)):
            if not value:
                raise KitError(f"sell needs {name} (or --from with a complete core)")
    emit(do_sell(kit, _core_from_args(kit, args)))
    return 0


def cmd_listings(args: argparse.Namespace) -> int:
    emit(do_listings(Kit.from_env(args.url)))
    return 0


def cmd_retire(args: argparse.Namespace) -> int:
    emit(do_retire(Kit.from_env(args.url), listing_id=args.listing_id))
    return 0


def cmd_inbox(args: argparse.Namespace) -> int:
    emit(do_inbox(Kit.from_env(args.url), countersign=not args.no_countersign))
    return 0


def cmd_deliver(args: argparse.Namespace) -> int:
    path = Path(args.file)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise KitError(f"cannot read the deliverable file {path}: {exc}") from exc
    emit(do_deliver(Kit.from_env(args.url), deal_id=args.deal, data=data))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    kit = Kit.from_env(args.url)
    argv_base: list[str] | None = None
    if args.exec_cmd:
        argv_base = shlex.split(args.exec_cmd)
        if not argv_base:
            raise KitError("--exec is empty after shell-style splitting")
    if args.interval < 1:
        raise KitError("--interval must be at least 1 second")
    mode = f"exec: {argv_base}" if argv_base else "poll-only (countersign + fetch inputs)"
    note(
        f"serve loop started ({mode}); interval {args.interval:.0f}s;"
        " survives marketplace outages with backoff; Ctrl-C stops"
    )
    return run_serve_loop(
        kit, argv_base=argv_base, interval_seconds=float(args.interval), once=bool(args.once)
    )


OWNER_NOTICE = (
    "OWNER AUTHORIZATION NOTICE: `budget set` records the OWNER's authorization to spend."
    " It creates a signed Intent Mandate; deals within its limits fund WITHOUT further"
    " confirmation. The mandate is signed with this agent's key (owner-key separation is"
    " deferred — residual R-AFD-1)."
)


def cmd_budget_set(args: argparse.Namespace) -> int:
    # Parse amounts first (pure; creates nothing).
    per_task_minor = parse_amount_minor(args.per_task)
    total_minor = parse_amount_minor(args.total)
    if per_task_minor <= 0 or total_minor <= 0:
        raise KitError("budget amounts must be positive")
    validate_budget_days(args.days)

    # OWNER GATE (D-12) — before anything is signed, sent, or written.
    note(OWNER_NOTICE)
    note(
        f"requested: per-task ceiling {format_display(per_task_minor)},"
        f" total budget {format_display(total_minor)}, valid {args.days} day(s)"
    )
    if args.i_am_the_owner:
        owner_ack = "--i-am-the-owner"
    elif sys.stdin.isatty():
        try:
            answer = input("Type 'yes' to confirm you are the owner and authorize this budget: ")
        except EOFError:
            answer = ""
        if answer.strip().lower() != "yes":
            raise KitError("budget set aborted: owner confirmation not given")
        owner_ack = "interactive-confirm"
    else:
        raise KitError(
            "budget set refused: non-interactive use requires --i-am-the-owner"
            " (this is an owner action, not an agent action)"
        )

    validate_budget_totals(total_minor, allow_over_grant=args.allow_over_grant)

    kit = Kit.from_env(args.url)
    kit.ensure_key()
    # Make sure the owner DID is registered (idempotent; also triggers the
    # sandbox grant best-effort server-side) so the mandate intake's KYA gate
    # cannot refuse a cold start.
    kit.register_envelope()

    exp = int(time.time()) + args.days * 86400
    claims = {
        "exp": exp,
        "price_ceiling": {"amount": per_task_minor, "unit": SETTLEMENT_UNIT},
        "total_budget": {"amount": total_minor, "unit": SETTLEMENT_UNIT},
    }
    mandate_id = kit.submit_intent_mandate(claims)

    audit_path = kit.append_audit(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "budget_set",
            "mandate_id": mandate_id,
            "owner_did": kit.did,
            "owner_ack": owner_ack,
            "price_ceiling_minor": per_task_minor,
            "total_budget_minor": total_minor,
            "unit": SETTLEMENT_UNIT,
            "exp_unix": exp,
            "days": args.days,
            "api_base": kit.base_url,
            "notice": "owner authorization recorded",
        }
    )
    note(f"owner authorization recorded; audit line appended to {audit_path}")
    note(f"mandate {mandate_id} active until exp={exp} (unix)")

    emit(
        {
            "mandate_id": mandate_id,
            "owner_did": kit.did,
            "price_ceiling": {
                "amount": per_task_minor,
                "unit": SETTLEMENT_UNIT,
                "display": format_display(per_task_minor),
            },
            "total_budget": {
                "amount": total_minor,
                "unit": SETTLEMENT_UNIT,
                "display": format_display(total_minor),
            },
            "exp_unix": exp,
            "audit_log": str(audit_path),
        }
    )
    return 0


# ---------------------------------------------------------------------------
# The optional MCP stdio server (D-11). Exposes the buyer flow as tools for an
# MCP-speaking agent. `budget` is an OWNER action and is NEVER exposed here
# (sec N-12) — the registry below is the single source the server builds from.
# ---------------------------------------------------------------------------

# Pinned and resolved ONCE at server start (cmd_mcp); None until then. The
# resolvers compare against these exact paths and never resolve them again:
# a later cwd change cannot widen the root, and neither can a symlink swapped
# into the root's own path after start (add-claude-code-plugin D-1 item 5).
_MCP_INPUT_ROOT: Path | None = None
_MCP_KIT_HOME: Path | None = None
# True when the server could not pin the kit home at start: every file-tool
# call then refuses for the server's lifetime (fail closed, never re-guessed).
_MCP_KIT_HOME_UNKNOWN = False

# Host instruction files (add-claude-code-plugin D-1 item 5): Claude Code
# loads these unfenced as standing instructions, so a deliverable must never
# land on one. Compared case-folded (see _is_host_instruction_file).
_HOST_INSTRUCTION_FILES = frozenset({"claude.md", "claude.local.md", "agents.md"})

# Python toolchain config files (add-claude-code-plugin D-3, Slice-2 security
# fix): uv reads uv.toml and pyproject.toml [tool.uv] from the working
# directory and its parents, pip reads pip.conf and setup.cfg, and a
# requirements*.txt decides what gets installed. A deliverable landing on one
# could point a later install at another package index. Compared folded like
# the instruction files (see _is_toolchain_config_file).
_TOOLCHAIN_CONFIG_FILES = frozenset({"uv.toml", "pyproject.toml", "setup.cfg", "pip.conf"})

# Files in the kit home whose bytes must never leave through a hire/deliver
# upload, even through a hard link outside the kit home (_is_kit_secret).
_KIT_SECRET_FILES = ("agent.pem", "session.json")

# Code points no path component may contain (security round 2, R2-B2), on top
# of every format character (Unicode category Cf: zero-width characters, bidi
# controls, the BOM, joiners, tag characters). Cf already covers git's
# utf8.c next_hfs_char list, the code points HFS+ ignores in names (so
# "\u200c.git" IS ".git" there). These ranges add the other default-ignorable
# code points, which are not Cf: the combining grapheme joiner, Hangul
# fillers, Khmer inherent vowels, Mongolian variation selectors, the reserved
# U+2065 and U+FFF0..U+FFF8 (Other_Default_Ignorable_Code_Point, category Cn),
# variation selectors and the whole tag/selector plane block. With the Cf test
# that is every Default_Ignorable_Code_Point in Unicode.
_IGNORABLE_RANGES = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2065, 0x2065),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0xE0000, 0xE0FFF),
)


def _input_root() -> Path:
    """The root that bounds the MCP file tools: hire/deliver read under it
    (sec S4-2), get_result writes under it (add-claude-code-plugin D-1). The
    server pins it at start; outside the server it comes from the environment."""
    if _MCP_INPUT_ROOT is not None:
        return _MCP_INPUT_ROOT
    return Path(os.environ.get(ENV_INPUT_ROOT) or os.getcwd()).resolve()


def _kit_home() -> Path:
    """The resolved kit home (agent key, session, listings, jobs), which no MCP
    file tool may touch; pinned at server start like the input root. Raises
    RuntimeError for the server's whole lifetime when pinning failed at start."""
    if _MCP_KIT_HOME_UNKNOWN:
        raise RuntimeError("the kit home could not be determined when the server started")
    if _MCP_KIT_HOME is not None:
        return _MCP_KIT_HOME
    return kit_home_from_env().resolve()


def _identity(path: Path) -> tuple[int, int] | None:
    """``(st_dev, st_ino)`` of what ``path`` names (symlinks followed); None if nothing is there.

    Any other error (a loop, no permission, an over-long name) propagates: the
    callers refuse rather than guess.
    """
    try:
        info = path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    return info.st_dev, info.st_ino


def _refuse_unsafe_root(root: Path) -> None:
    """Refuse a root that is a filesystem root, the user's home, or above it (D-1 item 5).

    Such a root puts the whole home (keys, cloud credentials, every other
    project) within reach of a model-chosen path. Compared by spelling and by
    filesystem identity (the root is the same directory as the home or one of
    its ancestors), so a letter-case variant of the home on a case-insensitive
    volume is the home too. Fails closed when the home cannot be determined or
    inspected. The text names no path: it reaches the MCP caller.
    """
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError) as exc:
        raise KitError(
            "refusing file access: cannot determine the home directory to check the"
            " server's input root against"
        ) from exc
    try:
        root_id = _identity(root)
        same_as_home_or_above = root_id is not None and any(
            _identity(folder) == root_id for folder in (home, *home.parents)
        )
    except OSError as exc:
        raise KitError(
            "refusing file access: cannot check the server's input root against the home directory"
        ) from exc
    if (
        root == Path(root.anchor)
        or home == root
        or home.is_relative_to(root)
        or same_as_home_or_above
    ):
        raise KitError(
            "refusing file access: the server's input root is a filesystem root, your home"
            " directory or a folder above it; start the server from a project directory or"
            f" set {ENV_INPUT_ROOT}"
        )


def _spelling(path: Path) -> tuple[str, ...]:
    """``path``'s components as a case- and normalization-insensitive volume compares them."""
    return tuple(
        unicodedata.normalize("NFC", unicodedata.normalize("NFC", part).casefold())
        for part in path.parts
    )


def _within(path: Path, base: Path) -> bool:
    """True when ``path`` is ``base`` or inside it, by spelling or by filesystem identity.

    Spelling: exact, then NFC-casefolded, which is all there is to compare
    while ``base`` does not exist yet (a write could otherwise create it under
    another letter case, and a case-insensitive volume would then serve it as
    ``base``). Identity: ``path`` or one of its existing ancestors is the same
    file as ``base`` (``(st_dev, st_ino)``, symlinks followed), whatever the
    spelling: a letter-case or Unicode-normalization variant on APFS or NTFS,
    a symlink, a bind mount. OSError propagates (the caller refuses).
    """
    if path.is_relative_to(base):
        return True
    wanted = _spelling(base)
    if _spelling(path)[: len(wanted)] == wanted:
        return True
    base_id = _identity(base)
    return base_id is not None and any(
        _identity(folder) == base_id for folder in (path, *path.parents)
    )


def _is_kit_secret(path: Path, kit_home: Path) -> bool:
    """True when ``path`` is the same file as the agent key or the cached session.

    A hard link elsewhere carries no spelling or ancestor tie to the kit home,
    so only the file's own identity shows it. OSError propagates.
    """
    target = _identity(path)
    return target is not None and any(
        _identity(kit_home / name) == target for name in _KIT_SECRET_FILES
    )


def _has_ignorable(name: str) -> bool:
    """True when ``name`` contains a format (Cf) or other default-ignorable code point."""
    return any(
        unicodedata.category(char) == "Cf"
        or any(low <= ord(char) <= high for low, high in _IGNORABLE_RANGES)
        for char in name
    )


def _folded_name(name: str) -> str:
    """``name`` the way a case-insensitive filesystem or Windows would open it.

    Compatibility-normalized and case-folded (so a long s, U+017F, reads as
    ``s``), with a ``:stream`` suffix and trailing dots or spaces dropped.
    """
    stem = name.split(":", 1)[0].rstrip(". ")
    return unicodedata.normalize("NFKC", stem).casefold()


def _is_host_instruction_file(name: str) -> bool:
    """True for ``CLAUDE.md``, ``CLAUDE.local.md`` or ``AGENTS.md`` in any letter case."""
    return _folded_name(name) in _HOST_INSTRUCTION_FILES


def _is_toolchain_config_file(name: str) -> bool:
    """True for ``uv.toml``, ``pyproject.toml``, ``setup.cfg``, ``pip.conf`` or
    ``requirements*.txt``, folded like the instruction files."""
    folded = _folded_name(name)
    return folded in _TOOLCHAIN_CONFIG_FILES or (
        folded.startswith("requirements") and folded.endswith(".txt")
    )


class _Confined(NamedTuple):
    """A path that passed the shared MCP file-tool rules."""

    path: Path  # resolved, inside the root
    mode: int | None  # its st_mode; None when nothing exists there yet
    names: tuple[str, ...]  # every component checked: as given, then as resolved


def _resolve_confined(path: str, root: Path, *, what: str) -> _Confined:
    """The rules every MCP file tool shares (sec S4-2; add-claude-code-plugin D-1).

    ``root`` is the pinned, already-resolved input root (``_input_root()``); it
    is NOT resolved again. Each refusal is a ``KitError``, raised before any
    network call, read or write, for:

    * a root that is a filesystem root, the home directory or above it;
    * a component holding an invisible or format code point (``_has_ignorable``),
      checked on the path as given BEFORE anything else looks at its names, and
      again as resolved;
    * a path ``resolve()`` cannot finish: a NUL byte, a symlink loop, an
      over-long name, a file used as a directory;
    * a path that resolves outside the root (symlinks are followed);
    * a ``..`` component, or any component that starts with ``.`` relative to
      the root, on the path as given AND as resolved (``.env``, ``.ssh/``,
      ``.git/hooks``, ``.claude/``), so neither the name nor a symlink gets
      past it;
    * a path inside the kit home, as given or as resolved, by spelling or by
      filesystem identity (``_within``), and a file that IS the agent key or
      the cached session under another name (``_is_kit_secret``).

    ``what`` names the caller's parameter in the refusal. The texts never name
    the absolute root (operator-local; printed on stderr at server start).
    """
    _refuse_unsafe_root(root)
    candidate = Path(path)
    given = candidate
    if candidate.is_absolute():
        # Judged relative to the root. An absolute path spelled through a
        # symlinked prefix (/var for /private/var) is not lexically under it;
        # for that one the resolved path decides.
        given = candidate.relative_to(root) if candidate.is_relative_to(root) else Path()
    invisible = (
        f"{what} {path!r} is refused: a path component holds an invisible or format character"
    )
    if any(_has_ignorable(part) for part in given.parts):
        raise KitError(invisible)
    unresolvable = f"{what} {path!r} cannot be resolved inside the server's input root"
    try:
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        # A NUL byte (ValueError) or, before Python 3.13, a symlink loop
        # (RuntimeError): refused legibly, never a crash.
        raise KitError(unresolvable) from exc
    if not resolved.is_relative_to(root):
        raise KitError(
            f"{what} {path!r} resolves outside the server's input root;"
            f" start the server from the right directory or set {ENV_INPUT_ROOT}"
        )
    landed = resolved.relative_to(root).parts
    if any(_has_ignorable(part) for part in landed):
        raise KitError(invisible)  # a symlink whose target name holds one
    names = (*given.parts, *landed)
    if ".." in candidate.parts or any(name.startswith(".") for name in names):
        raise KitError(
            f"{what} {path!r} is refused: no '..' and no path component that starts with '.'"
            " inside the server's input root"
        )
    try:
        kit_home = _kit_home()
    except (OSError, RuntimeError) as exc:
        raise KitError("refusing file access: cannot determine the kit home") from exc
    try:
        in_kit_home = _within(resolved, kit_home) or _within(root / given, kit_home)
        kit_secret = not in_kit_home and _is_kit_secret(resolved, kit_home)
    except OSError as exc:
        raise KitError(unresolvable) from exc
    if in_kit_home:
        raise KitError(
            f"{what} {path!r} is refused: it is inside the kit home (agent key and session)"
        )
    if kit_secret:
        raise KitError(
            f"{what} {path!r} is refused: it is the same file as the kit's agent key or session"
        )
    try:
        mode: int | None = resolved.stat().st_mode
    except FileNotFoundError:
        mode = None  # not there yet: a new output file, or a missing input
    except (OSError, ValueError) as exc:
        # A symlink loop (stat() raises ELOOP; Python 3.13+ resolve() does
        # not), an over-long name, a file used as a directory. An explicit
        # stat(), because Path.exists() swallows these on Python 3.13+.
        raise KitError(unresolvable) from exc
    return _Confined(resolved, mode, names)


def resolve_input_path(input_path: str, root: Path, *, what: str = "input_path") -> Path:
    """Resolve a path the MCP ``hire``/``deliver`` tool may READ under ``root`` (sec S4-2).

    The shared rules (``_resolve_confined``): what it reads goes to a
    counterparty, so ``.env``, ``.ssh/``, ``.aws/`` and the kit home stay out
    of reach. The CLI is deliberately NOT routed through this — a human
    invoking the CLI chooses their own paths; this bounds what an LLM-driven
    MCP caller can make the kit read.
    """
    return _resolve_confined(input_path, root, what=what).path


def read_confined_input(path: str, root: Path, *, what: str) -> bytes:
    """Read a file for the MCP ``hire``/``deliver`` tool (``resolve_input_path``).

    A read that fails (a missing file, a directory) is a ``KitError`` carrying
    the OS reason only, never the absolute path. Residual: a small window
    remains between the final check and the read, as between the final check
    and the rename in ``write_confined_output``; a process racing on the same
    tree could swap a symlink in during it.
    """
    resolved = resolve_input_path(path, root, what=what)
    try:
        return resolved.read_bytes()
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise KitError(f"{what} {path!r} cannot be read: {reason}") from exc


def resolve_output_path(out_path: str, root: Path) -> Path:
    """Resolve where the MCP ``get_result`` tool may write (add-claude-code-plugin D-1).

    The shared rules (``_resolve_confined``), so the counterparty-authored
    bytes stay out of ``.git/hooks``, ``.claude/``, ``.mcp.json``, ``.env`` and
    other files that configure or execute, plus the rules for writing:

    * no component named ``CLAUDE.md``, ``CLAUDE.local.md`` or ``AGENTS.md``,
      in any letter case and at any depth, as given or as resolved: Claude
      Code loads those as standing instructions;
    * no component named ``uv.toml``, ``pyproject.toml``, ``setup.cfg``,
      ``pip.conf`` or ``requirements*.txt``, folded the same way and at any
      depth: they configure the Python toolchain (package index, pins);
    * the target is a regular file or does not exist yet (not the root, not a
      directory), and an existing one is writable.

    Every refusal is a ``KitError`` raised before any write. The CLI
    ``result --out`` is NOT routed through this: a human types its paths.
    """
    confined = _resolve_confined(out_path, root, what="out_path")
    if any(_is_host_instruction_file(name) for name in confined.names):
        raise KitError(
            f"out_path {out_path!r} is refused: CLAUDE.md, CLAUDE.local.md and AGENTS.md are"
            " host instruction files, in any letter case"
        )
    if any(_is_toolchain_config_file(name) for name in confined.names):
        raise KitError(
            f"out_path {out_path!r} is refused: uv.toml, pyproject.toml, setup.cfg, pip.conf and"
            " requirements*.txt configure the Python toolchain, in any letter case"
        )
    mode = confined.mode
    if confined.path == root or (mode is not None and not stat.S_ISREG(mode)):
        raise KitError(f"out_path {out_path!r} must name a file inside the server's input root")
    if mode is not None and not os.access(confined.path, os.W_OK):
        raise KitError(f"out_path {out_path!r} names a read-only file; choose another path")
    return confined.path


def write_confined_output(out_path: str, root: Path, data: bytes) -> Path:
    """Write a verified deliverable for the MCP ``get_result`` tool (D-1).

    The destination is re-checked right before the write: the download can
    take up to the tool's timeout, and the tree may change meanwhile (a
    symlink planted at the target). The bytes go to a fresh temp file
    (``O_EXCL|O_NOFOLLOW``, binary on Windows) beside the target, which is
    then renamed into place, so an existing name is replaced rather than
    written through: a hard link or a symlink at the target cannot carry the
    bytes elsewhere. Mirrors ``write_job_input``'s discipline. A failed write
    is a ``KitError`` carrying the OS reason only, never the absolute path.
    Residual: a small window remains between that final check and the rename
    (as between the final check and the read for hire/deliver); a process
    racing on the same tree could swap a symlink into the parent path.
    """
    target = resolve_output_path(out_path, root)
    # Fixed-length name: a long target name cannot push it past NAME_MAX.
    tmp = target.parent / f".lhub-kit-{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, flags, 0o666)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    except OSError as exc:
        # strerror only: the absolute root is operator-local context and this
        # text reaches the MCP caller (sec re-review NIT 2).
        reason = exc.strerror or type(exc).__name__
        raise KitError(f"cannot write out_path {out_path!r}: {reason}") from exc
    return target


MCP_TOOL_NAMES: tuple[str, ...] = (
    "find_services",
    "hire",
    "get_result",
    "accept",
    "dispute",
    "balance",
    "sell",
    "my_listings",
    "inbox",
    "deliver",
)


def _tool_annotation(
    title: str,
    *,
    read_only: bool = False,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
) -> dict[str, str | bool]:
    """One D-1 row in MCP wire form: the title and all four hints, each explicit.

    A hint left out would read as the protocol default, and two of those
    defaults (destructive, open world) are true.
    """
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    }


# Each stdio tool's title and MCP ToolAnnotations: add-claude-code-plugin
# design D-1, which applies the rules of add-directory-listing-readiness D-1
# to what each kit tool composes. Read-only: the call changes no server state
# (balance and my_listings are not: first use creates the key, registers the
# DID and triggers the one-time grant). Destructive: the call can irreversibly
# move funds or end something, or writes counterparty bytes over a project
# file (get_result). Idempotent: a repeat with the same arguments has no
# further effect (deterministic idempotency keys, natural replays). inbox is
# not: its key makes a replay of the same proposal safe, but a repeat call
# countersigns proposals that arrived in between (D-1 item 5). Open world:
# the call reaches a counterparty. Hints for clients that gate tool calls;
# nothing server-side depends on them.
MCP_TOOL_ANNOTATIONS: dict[str, dict[str, str | bool]] = {
    "find_services": _tool_annotation("Find services", read_only=True, idempotent=True),
    "hire": _tool_annotation("Hire a service", destructive=True, open_world=True),
    "get_result": _tool_annotation("Get result", destructive=True, idempotent=True),
    "accept": _tool_annotation(
        "Accept delivery", destructive=True, idempotent=True, open_world=True
    ),
    "dispute": _tool_annotation("Dispute deal", destructive=True, idempotent=True, open_world=True),
    "balance": _tool_annotation("Get balance", idempotent=True),
    "sell": _tool_annotation("Create listing"),
    "my_listings": _tool_annotation("List my listings", idempotent=True),
    "inbox": _tool_annotation("Check seller inbox", destructive=True, open_world=True),
    "deliver": _tool_annotation("Deliver result", idempotent=True, open_world=True),
}


def mcp_find_services(category: str = "", free_text: str = "", limit: int = 10) -> dict[str, Any]:
    """Search the LHUB marketplace for service listings."""
    return do_find(Kit.from_env(), category=category, free_text=free_text, limit=limit)


def mcp_hire(
    listing_id: str,
    input_path: str,
    max_price: str,
    provider: str = "",
    quantity: int = 0,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Hire a listing: open a deal, upload the input file, sign within max_price, wait.

    input_path must stay inside the server's input root (the working directory
    at server start, or $LHUB_KIT_INPUT_ROOT), with no '..' and no path
    component that starts with '.'.
    """
    data = read_confined_input(input_path, _input_root(), what="input_path")
    return do_hire(
        Kit.from_env(),
        listing_id=listing_id,
        input_bytes=data,
        max_price_minor=parse_amount_minor(max_price),
        pinned_provider=provider or None,
        quantity=quantity or None,
        timeout_seconds=float(timeout_seconds),
        poll_seconds=3.0,
    )


def mcp_get_result(deal_id: str, out_path: str, timeout_seconds: int = 60) -> dict[str, Any]:
    """Download the deliverable for a deal, verify it against the proof hash, save it.

    out_path must name a file inside the server's input root (the working
    directory at server start, or $LHUB_KIT_INPUT_ROOT; a relative path is
    relative to it), with no '..', no path component that starts with '.',
    no CLAUDE.md, CLAUDE.local.md or AGENTS.md, and no uv.toml,
    pyproject.toml, setup.cfg, pip.conf or requirements*.txt; any other path
    is refused before the download.
    """
    root = _input_root()
    # D-1: a refused path fails HERE — before any network call or write.
    resolve_output_path(out_path, root)
    return do_result(
        Kit.from_env(),
        deal_id=deal_id,
        out_path=Path(out_path),
        timeout_seconds=float(timeout_seconds),
        poll_seconds=3.0,
        write_out=lambda data: write_confined_output(out_path, root, data),
    )


def mcp_accept(deal_id: str) -> dict[str, Any]:
    """Accept a verified deliverable, releasing escrowed funds to the provider."""
    return do_accept(Kit.from_env(), deal_id=deal_id)


def mcp_dispute(deal_id: str, reason: str) -> dict[str, Any]:
    """Open a dispute on a deal (freezes it for arbitration)."""
    return do_dispute(Kit.from_env(), deal_id=deal_id, reason=reason)


def mcp_balance() -> dict[str, Any]:
    """Read this agent's LHUB-DEV balance."""
    return do_balance(Kit.from_env())


def mcp_sell(
    category: str,
    title: str,
    summary: str,
    price: str,
    unit: str,
    model: str = "per_unit",
    min_charge: str = "",
    input_desc: str = "",
    input_types: str = "",
    deliverable_desc: str = "",
    deliverable_type: str = "",
    turnaround_hours: int = 24,
) -> dict[str, Any]:
    """List a service: build the core locally, sign it, create and activate the listing."""
    kit = Kit.from_env()
    kit.ensure_key()
    core = build_listing_core(
        own_did=kit.did,
        endpoint=_redact_url(kit.base_url) + MCP_PATH,  # never publish userinfo
        category=category,
        title=title,
        summary=summary,
        price=price,
        unit=unit,
        model=model,
        min_charge=min_charge,
        input_desc=input_desc,
        input_types=input_types,
        deliverable_desc=deliverable_desc,
        deliverable_type=deliverable_type,
        turnaround_hours=turnaround_hours,
    )
    return do_sell(kit, core)


def mcp_my_listings() -> dict[str, Any]:
    """List this agent's own (non-retired) service listings."""
    return do_listings(Kit.from_env())


def mcp_inbox(countersign: bool = True) -> dict[str, Any]:
    """Poll the seller inbox once: countersign matching proposals, fetch funded inputs."""
    return do_inbox(Kit.from_env(), countersign=countersign)


def mcp_deliver(deal_id: str, file_path: str) -> dict[str, Any]:
    """Upload a deliverable file for a funded deal and submit its Tier-0 proof.

    file_path must stay inside the server's input root (the working directory
    at server start, or $LHUB_KIT_INPUT_ROOT), with no '..' and no path
    component that starts with '.'.
    """
    data = read_confined_input(file_path, _input_root(), what="file_path")
    return do_deliver(Kit.from_env(), deal_id=deal_id, data=data)


def mcp_tool_functions() -> dict[str, Callable[..., dict[str, Any]]]:
    """The stdio server's full tool registry — the owner-only `budget` is absent by design."""
    return {
        "find_services": mcp_find_services,
        "hire": mcp_hire,
        "get_result": mcp_get_result,
        "accept": mcp_accept,
        "dispute": mcp_dispute,
        "balance": mcp_balance,
        "sell": mcp_sell,
        "my_listings": mcp_my_listings,
        "inbox": mcp_inbox,
        "deliver": mcp_deliver,
    }


def _kit_errors_as_tool_errors(
    fn: Callable[..., dict[str, Any]], tool_error: type[Exception]
) -> Callable[..., dict[str, Any]]:
    """Wrap one MCP tool so a ``KitError`` reaches the caller as the CLI's failure JSON.

    mcp 2.x treats any exception other than its ``ToolError`` as a crash and
    keeps the text server-side, so an MCP caller used to see only "Error
    executing tool <name>": no reason, no retryable code, not the deal a failed
    ``hire`` left behind (D-4, orchestrator ruling 2026-11-16). A ``KitError``
    is therefore re-raised as the SDK's ``ToolError`` whose message is exactly
    the JSON object the CLI prints for that failure (``failure_payload``); the
    SDK prefixes "Error executing tool <name>: ". No new exposure: the CLI
    already prints the same text to the same operator. Only ``KitError`` is
    converted; any other exception keeps the SDK's own handling (on 2.x the
    generic crash text). ``functools.wraps`` keeps the signature the SDK
    builds the tool's input schema from.
    """

    @functools.wraps(fn)
    def tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return fn(*args, **kwargs)
        except KitError as exc:
            raise tool_error(json_text(failure_payload(exc))) from exc

    return tool


def _mcp_tool_metadata(add_tool: Callable[..., Any], name: str) -> dict[str, Any]:
    """The D-1 ``title=`` and ``annotations=`` keywords for one tool, as far as this mcp takes them.

    mcp 2.x (``MCPServer.add_tool``) and a recent 1.x ``FastMCP.add_tool``
    accept both. An older 1.x accepts neither, or only ``annotations``:
    whatever its ``add_tool`` does not accept is omitted, so the server still
    builds and the kit stays importable on every supported mcp (D-1). The
    title is inside the annotations too, which is where an mcp without the
    ``title=`` keyword can still carry it.
    """
    row = MCP_TOOL_ANNOTATIONS[name]
    try:
        accepted = inspect.signature(add_tool).parameters
    except (TypeError, ValueError):  # not introspectable: register without metadata
        return {}
    metadata: dict[str, Any] = {}
    if "title" in accepted:
        metadata["title"] = row["title"]
    if "annotations" in accepted:
        try:
            from mcp.types import ToolAnnotations
        except ImportError:  # an mcp too old to model annotations
            return metadata
        metadata["annotations"] = ToolAnnotations.model_validate(row)
    return metadata


def build_mcp_server() -> Any:
    """Build the MCP stdio server over the tool registry (import guarded).

    Supports both mcp 2.x (``MCPServer``) and 1.x (``FastMCP`` — renamed in
    2.x), so ``pip install mcp`` works whichever major an agent gets. On both,
    a kit failure reaches the caller as the CLI's failure JSON
    (``_kit_errors_as_tool_errors``). Each tool registers with its D-1 title
    and annotations where the installed ``add_tool`` accepts them
    (``_mcp_tool_metadata``).
    """
    server_cls: Any
    tool_error: type[Exception]
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError

        server_cls = MCPServer
        tool_error = ToolError
    except ImportError:
        try:
            # mcp 1.x. In a 2.x install these modules are only a tombstone
            # that raises ModuleNotFoundError, so a 2.x-typed mypy cannot see
            # them — the runtime fallback is still correct on 1.x.
            from mcp.server.fastmcp import FastMCP  # type: ignore[attr-defined]
            from mcp.server.fastmcp.exceptions import (  # type: ignore[import-not-found]
                ToolError as FastMCPToolError,
            )

            server_cls = FastMCP
            tool_error = FastMCPToolError
        except ImportError as exc:
            raise KitError(
                'the `mcp` package is required for the stdio server: pip install "mcp"'
            ) from exc
    server = server_cls("lhub")
    for name, fn in mcp_tool_functions().items():
        server.add_tool(
            _kit_errors_as_tool_errors(fn, tool_error),
            name=name,
            description=fn.__doc__ or name,
            **_mcp_tool_metadata(server.add_tool, name),
        )
    return server


def cmd_mcp(args: argparse.Namespace) -> int:
    if args.url:
        os.environ[ENV_BASE_URL] = args.url
    # Pin the file tools' input root and the kit home for the server's
    # lifetime, resolved once here and never again (sec S4-2, D-1 item 5).
    global _MCP_INPUT_ROOT, _MCP_KIT_HOME, _MCP_KIT_HOME_UNKNOWN
    _MCP_INPUT_ROOT = Path(os.environ.get(ENV_INPUT_ROOT) or os.getcwd()).resolve()
    try:
        _MCP_KIT_HOME = kit_home_from_env().resolve()
    except (OSError, RuntimeError):
        # Unknown kit home: every file-tool call refuses for the server's
        # whole lifetime (_kit_home raises), even if it could be found later.
        _MCP_KIT_HOME_UNKNOWN = True
        note(
            "warning: cannot determine the kit home; hire, deliver and get_result"
            " will refuse every call"
        )
    server = build_mcp_server()
    note(f"lhub-kit MCP server on stdio (marketplace: {_redact_url(Kit.from_env().base_url)})")
    note("tools: " + ", ".join(MCP_TOOL_NAMES) + " — budget is owner-only and not exposed")
    note(
        f"input root (hire/deliver read, get_result writes): {_MCP_INPUT_ROOT}"
        f" (override with ${ENV_INPUT_ROOT})"
    )
    try:
        _refuse_unsafe_root(_MCP_INPUT_ROOT)
    except KitError as exc:
        note(f"warning: hire, deliver and get_result will refuse every call — {exc}")
    server.run()
    return 0


# ---------------------------------------------------------------------------
# argparse wiring.
# ---------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that keeps stdout machine-readable on usage errors."""

    def error(self, message: str) -> NoReturn:
        sys.stdout.write(json.dumps({"error": f"usage: {message}"}) + "\n")
        sys.stderr.write(f"error: {message}\n")
        sys.stderr.write(self.format_usage())
        raise SystemExit(2)


def _add_url(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--url",
        default=None,
        help=f"marketplace base URL (default ${ENV_BASE_URL} or {DEFAULT_BASE_URL})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="lhub.py",
        description="LHUB agent kit — buy and sell services on an LHUB marketplace from one file.",
    )
    parser.add_argument("--version", action="version", version=f"lhub-kit {KIT_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create the key, register the DID, show DID + balance")
    _add_url(p)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("find", help="search service listings")
    _add_url(p)
    p.add_argument(
        "--category", default="", help="category path, e.g. digital_services/code/review"
    )
    p.add_argument("--free-text", default="", help="free-text query")
    p.add_argument("--limit", type=int, default=10, help="max results (default 10)")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("hire", help="buy a service: open deal, upload input, sign, wait")
    _add_url(p)
    p.add_argument("--listing", required=True, help="listing id (from `find`)")
    p.add_argument("--input", required=True, help="path of the job input file to send")
    p.add_argument(
        "--max-price",
        required=True,
        help='maximum total price as a decimal string, e.g. "1.00" (LHUB-DEV)',
    )
    p.add_argument("--provider", default=None, help="pin the expected provider DID (from `find`)")
    p.add_argument(
        "--quantity",
        type=int,
        default=None,
        help="units for per-unit listings (defaults to 1 when the listing is per-unit)",
    )
    p.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for countersign")
    p.add_argument("--poll", type=float, default=3.0, help="poll interval seconds")
    p.set_defaults(func=cmd_hire)

    p = sub.add_parser("status", help="read a deal (state, amounts, next step)")
    _add_url(p)
    p.add_argument("--deal", required=True, help="deal id")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("result", help="download the deliverable and verify it against the proof")
    _add_url(p)
    p.add_argument("--deal", required=True, help="deal id")
    p.add_argument("--out", required=True, help="where to write the verified deliverable")
    p.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for a proof")
    p.add_argument("--poll", type=float, default=3.0, help="poll interval seconds")
    p.set_defaults(func=cmd_result)

    p = sub.add_parser("accept", help="accept a verified deliverable (releases funds)")
    _add_url(p)
    p.add_argument("--deal", required=True, help="deal id")
    p.set_defaults(func=cmd_accept)

    p = sub.add_parser("dispute", help="dispute a deal (freezes it for arbitration)")
    _add_url(p)
    p.add_argument("--deal", required=True, help="deal id")
    p.add_argument("--reason", required=True, help="what went wrong (free text)")
    p.set_defaults(func=cmd_dispute)

    p = sub.add_parser("balance", help="show this agent's LHUB-DEV balance")
    _add_url(p)
    p.set_defaults(func=cmd_balance)

    p = sub.add_parser("sell", help="list a service: build core, sign, create + activate")
    _add_url(p)
    p.add_argument(
        "--from",
        dest="from_file",
        default=None,
        help="path of a complete listing-core JSON (instead of the flags below)",
    )
    p.add_argument("--category", default="", help="leaf category (see list_categories)")
    p.add_argument("--title", default="", help="display name for the listing")
    p.add_argument("--summary", default="", help="what the service does (one sentence)")
    p.add_argument("--price", default="", help='price per unit as a decimal string, e.g. "0.10"')
    p.add_argument("--unit", default="", help='billable unit identifier, e.g. "file"')
    p.add_argument(
        "--model", choices=("per_unit", "flat"), default="per_unit", help="pricing model"
    )
    p.add_argument(
        "--min-charge",
        default="",
        help="optional minimum total charge (must be at least the price)",
    )
    p.add_argument("--input-desc", default="", help="what the input file should contain")
    p.add_argument("--input-types", default="", help="accepted input media types, comma-separated")
    p.add_argument("--deliverable-desc", default="", help="what the deliverable contains")
    p.add_argument("--deliverable-type", default="", help="deliverable media type")
    p.add_argument("--turnaround-hours", type=int, default=24, help="delivery SLA in hours (1-168)")
    p.set_defaults(func=cmd_sell)

    p = sub.add_parser("listings", help="list this agent's own listings")
    _add_url(p)
    p.set_defaults(func=cmd_listings)

    p = sub.add_parser("retire", help="retire one of this agent's listings")
    _add_url(p)
    p.add_argument("listing_id", help="the listing UUID to retire")
    p.set_defaults(func=cmd_retire)

    p = sub.add_parser(
        "inbox", help="poll the seller inbox once: countersign + fetch funded inputs"
    )
    _add_url(p)
    p.add_argument(
        "--no-countersign",
        action="store_true",
        help="only report the to-do list; sign nothing",
    )
    p.set_defaults(func=cmd_inbox)

    p = sub.add_parser("deliver", help="upload a deliverable and submit its Tier-0 proof")
    _add_url(p)
    p.add_argument("deal", help="deal id")
    p.add_argument("file", help="path of the deliverable file (max 160 KiB)")
    p.set_defaults(func=cmd_deliver)

    p = sub.add_parser("serve", help="loop the inbox; with --exec, run a command per job")
    _add_url(p)
    p.add_argument(
        "--exec",
        dest="exec_cmd",
        default="",
        help="command to run per funded job (shlex-split, no shell; input path appended)",
    )
    p.add_argument("--interval", type=float, default=30.0, help="poll interval seconds")
    p.add_argument("--once", action="store_true", help="one round, then exit")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("budget", help="owner actions: pre-authorize spending")
    budget_sub = p.add_subparsers(dest="budget_command", required=True)
    ps = budget_sub.add_parser("set", help="create a spending mandate (OWNER action)")
    _add_url(ps)
    ps.add_argument("--per-task", required=True, help='per-deal ceiling, e.g. "1.00"')
    ps.add_argument("--total", required=True, help='total budget, e.g. "5.00"')
    ps.add_argument(
        "--days",
        type=int,
        required=True,
        help=f"validity in days (1-{MAX_BUDGET_DAYS})",
    )
    ps.add_argument(
        "--i-am-the-owner",
        action="store_true",
        help="assert owner authorization non-interactively (required without a terminal)",
    )
    ps.add_argument(
        "--allow-over-grant",
        action="store_true",
        help=f"allow --total above the sandbox grant ({format_display(SANDBOX_GRANT_MINOR)})",
    )
    ps.set_defaults(func=cmd_budget_set)

    p = sub.add_parser("mcp", help="run the kit as an MCP stdio server (needs `pip install mcp`)")
    _add_url(p)
    p.set_defaults(func=cmd_mcp)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] = args.func
    try:
        return func(args)
    except KitError as exc:
        # The JSON object is built by failure_payload, shared with the MCP
        # server: `error` (a KitFailure's payload before it), `code` +
        # `retryable: true` for a retryable refusal (D-4), then a failed
        # hire's deal_id/stage/next_step, which never replace those.
        emit(failure_payload(exc))
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except KeyboardInterrupt:
        emit({"error": "interrupted"})
        return 130


if __name__ == "__main__":
    sys.exit(main())
