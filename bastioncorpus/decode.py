"""Decode and rescan: find encoded text and return what it says.

An obfuscation jailbreak hides an instruction in an encoding the model reads
fluently but a text detector does not (binary, base64, hex, rot13...). Scanners
call `variants(text)` and run their usual checks on every decoded view too.

    run-based   only the encoded span is decoded (cheap, used everywhere):
                base64 / base64url, base32, hex, binary, ascii85 (<~ ~>), base85,
                Morse, percent-encoding, \\u / \\x escapes, Unicode tag characters
    transforms  the whole text is rewritten (opt-in, `transforms=True`; the user
                input guard uses them): rot13, leet folding, reversed, spaced letters

A decoded run is kept only if it reads like text: valid UTF-8, mostly printable,
with a run of letters. JWTs, hashes, keys, UUIDs and image data decode to noise
and are dropped. Decoded text is decoded again up to `max_depth` (base64 of hex).

Bounded: at most MAX_RUNS runs, decoded output at most 4x the input and at most
MAX_OUTPUT characters; linear regexes only. Never raises.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass

MAX_RUNS = 256
MAX_OUTPUT = 1_000_000
MIN_TEXT = 4
PRINTABLE_RATIO = 0.85


@dataclass(frozen=True)
class Decoded:
    encoding: str  # e.g. "base64", "hex>base64" for a chain
    text: str


_B64 = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}")
_B32 = re.compile(r"(?<![A-Z2-7=])[A-Z2-7]{16,}={0,6}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_HEX_SPACED = re.compile(r"(?:[0-9A-Fa-f]{2}[ :,]){7,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_BIN = re.compile(r"(?:[01]{8}[ ,]?){4,}")
# Every repeat below is bounded or anchored on a literal, so a scan stays linear in
# the input (an unbounded `[^%]*` before a `%` re-scans from every start: quadratic).
_A85 = re.compile(r"<~[!-u\s]{4,65536}?~>")
_B85 = re.compile(r"(?<!\S)[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{20,}(?!\S)")
_MORSE = re.compile(r"(?:[.\-]{1,7}(?: {1,3}| ?/ ?)){3,}[.\-]{1,7}")
_PERCENT = re.compile(r"(?:[^\s%]{0,64}%[0-9A-Fa-f]{2}){3,}[^\s%]{0,64}")
_ESCAPES = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}){4,}")
_TAGS = re.compile("[\U000E0020-\U000E007E]{4,}")
_LETTERS = re.compile(r"[A-Za-z]{3}")
_SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")

_MORSE_TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g",
    "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n",
    "---": "o", ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u",
    "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
    "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", "-..-.": "/", ".--.-.": "@",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                       "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"})


def _readable(raw) -> str | None:
    """The decoded value as text if it reads like text, else None."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return None
    text = raw.strip()
    if len(text) < MIN_TEXT or not _LETTERS.search(text):
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\t\n\r")
    return text if printable / len(text) >= PRINTABLE_RATIO else None


def _b64(run: str):
    s = run.rstrip("=")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    alt = b"-_" if ("-" in s or "_" in s) else None
    if alt and ("+" in s or "/" in s):
        return None
    return base64.b64decode(s, altchars=alt, validate=True)


def _b32(run: str):
    s = run.rstrip("=")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _hex(run: str):
    s = re.sub(r"[^0-9A-Fa-f]", "", run[2:] if run[:2].lower() == "0x" else run)
    return bytes.fromhex(s) if len(s) % 2 == 0 else None


def _bin(run: str):
    bits = re.sub(r"[^01]", "", run)
    if len(bits) % 8:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _a85(run: str):
    return base64.a85decode(run, adobe=True)


def _b85(run: str):
    if run.isalnum():  # plain words/base64 runs: base85 needs punctuation
        return None
    return base64.b85decode(run)


def _morse(run: str):
    words = re.split(r"\s*/\s*| {3,}", run.strip())
    out = []
    for w in words:
        letters = [_MORSE_TABLE.get(code) for code in w.split()]
        if not letters or None in letters:
            return None
        out.append("".join(letters))
    return " ".join(out)


def _percent(run: str):
    return urllib.parse.unquote(run, errors="strict")


def _escapes(run: str):
    return codecs.decode(run, "unicode_escape")


def _tags(run: str):
    return "".join(chr(ord(c) - 0xE0000) for c in run)


_RUN_DECODERS = (
    ("binary", _BIN, _bin),
    ("hex", _HEX_SPACED, _hex),
    ("hex", _HEX, _hex),
    ("base32", _B32, _b32),
    ("base64", _B64, _b64),
    ("ascii85", _A85, _a85),
    ("base85", _B85, _b85),
    ("morse", _MORSE, _morse),
    ("percent", _PERCENT, _percent),
    ("escape", _ESCAPES, _escapes),
    ("tags", _TAGS, _tags),
)


def _transforms(text: str) -> list[Decoded]:
    out = [Decoded("rot13", codecs.decode(text, "rot13")),
           Decoded("reversed", text[::-1])]
    leet = text.translate(_LEET)
    if leet != text:
        out.append(Decoded("leet", leet))
    spaced = _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)
    if spaced != text:
        out.append(Decoded("spaced", spaced))
    return out


def variants(text: str, *, transforms: bool = False, max_depth: int = 2) -> list[Decoded]:
    """Every decoded view of `text`, deduplicated, in a stable order. `[]` when
    nothing decodes. `transforms=True` adds the whole-text rewrites."""
    if not isinstance(text, str) or not text:
        return []
    budget = min(4 * len(text), MAX_OUTPUT)
    seen = {text}
    out: list[Decoded] = []
    runs = 0

    def add(d: Decoded) -> bool:
        nonlocal budget
        if d.text in seen or len(d.text) > budget:
            return False
        seen.add(d.text)
        budget -= len(d.text)
        out.append(d)
        return True

    frontier = [Decoded("", text)]
    for _depth in range(max(1, max_depth)):
        nxt: list[Decoded] = []
        for item in frontier:
            for name, rx, decode in _RUN_DECODERS:
                for m in rx.finditer(item.text):
                    runs += 1
                    if runs > MAX_RUNS or budget <= 0:
                        return out
                    run = m.group(0)
                    try:
                        decoded = _readable(decode(run))
                    except (ValueError, binascii.Error, UnicodeDecodeError, OverflowError):
                        continue
                    if decoded is None or decoded.strip() == run.strip():
                        continue
                    d = Decoded(f"{item.encoding}>{name}" if item.encoding else name, decoded)
                    if add(d):
                        nxt.append(d)
        frontier = nxt
        if not frontier:
            break
    if transforms:
        for d in _transforms(text):
            if _readable(d.text) is not None:
                add(d)
    return out
