"""Decode and rescan: find encoded text and return what it says.

An obfuscation jailbreak hides an instruction in an encoding the model reads
fluently but a text detector does not (binary, base64, hex, rot13...). Scanners
call `variants(text)` and run their usual checks on every decoded view too.

    run-based   only the encoded span is decoded (cheap, used everywhere):
                base64 / base64url (also line-wrapped or spaced), base32, hex
                (plain, spaced, 0x-prefixed), binary (8- and 7-bit, misaligned),
                ascii85, base85, Morse, \\u / \\U / \\x escapes, Unicode tag characters
    text views  whole-text decodes that only run when the text contains them:
                percent-escapes and backslash-escapes mixed into normal words
    transforms  whole-text rewrites (opt-in, `transforms=True`; the user-input
                guard uses them): rot13, leet folding, reversed, spaced letters

A decoded run is reported only if it reads like text: valid UTF-8 (or UTF-16),
mostly printable, with a run of letters. JWT signatures, hashes, keys, UUIDs and
image data decode to noise and are dropped. Decoded text that is only an
intermediate layer (e.g. the hex inside base64) is decoded again up to
`max_depth` even when it does not read like prose.

Bounds: a whole run is decoded and returned in overlapping PER_RUN-sized chunks
(a payload anywhere in a huge run is seen whole); total output at most MAX_OUTPUT
chars; every regex is linear (about 0.2-0.7 s per MB of input). Never raises.

Limit: decodable text past MAX_OUTPUT chars is not returned. Scanners must cap the
input they hand over and fail closed above it (bastionmesh limits.max_message_chars,
bastiongate's decode cap), never silently scan a prefix.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass

PER_RUN = 65_536
MAX_OUTPUT = 4_000_000
MIN_TEXT = 4
PRINTABLE_RATIO = 0.85


@dataclass(frozen=True)
class Decoded:
    encoding: str  # e.g. "base64", "hex>base64" for a chain
    text: str


# Every repeat is bounded or anchored on a literal, so a scan stays linear in the
# input (an unbounded `[^%]*` before a `%` re-scans from every start: quadratic).
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/_-]{16,}={0,2}")
# starts only at a token boundary: a start inside a long run would scan 128 chars and
# backtrack at every position (about 1 s per MB of unbroken base64)
_B64_WRAPPED = re.compile(r"(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{4,128}[ \t\r\n]{1,4}){3,}[A-Za-z0-9+/_-]{2,128}={0,2}")
_B32 = re.compile(r"(?<![A-Za-z2-7])[A-Za-z2-7]{16,}={0,6}")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
_HEX_SEPARATED = re.compile(
    r"(?:(?:0x|\\x)?[0-9A-Fa-f]{2,8}[ \t\r\n,:;]{1,4}){7,}(?:0x|\\x)?[0-9A-Fa-f]{2,8}(?![0-9A-Fa-f])")
_BIN = re.compile(r"(?:(?:0b)?[01]{7,8}[ \t\r\n,]{0,4}){4,}")
_A85 = re.compile(r"<~[!-u\s]{4,65536}?~>")
_A85_BARE = re.compile(r"(?<![!-u])[!-u]{20,}(?![!-u])")  # ascii85 without <~ ~>
_B85 = re.compile(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{20,}")
_MORSE = re.compile(r"(?:[.\-]{1,7}(?: {1,3}| ?/ ?)){3,}[.\-]{1,7}")
_ESCAPES = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}){4,}")
_TAGS = re.compile("[\U000E0001\U000E0020-\U000E007F]{4,}")
_LETTERS = re.compile(r"[A-Za-z]{3}")
_SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_]){2,}[A-Za-z]\b")  # 3+ letters; 2+ spaces = word gap
_PCT_ONE = re.compile(r"%[0-9A-Fa-f]{2}")
_PCT_GAP = re.compile(r"(%[0-9A-Fa-f]{2})[ \t]{1,4}(?=%[0-9A-Fa-f]{2})")  # "%69 %67" -> "%69%67"
_ESC_ONE = re.compile(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2}")
_SURROGATE = re.compile("[\ud800-\udfff]")

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


def _as_text(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw)
        if len(raw) % 2 == 0 and raw.count(0) * 4 >= len(raw):  # UTF-16 text (NULs are valid UTF-8)
            for enc in ("utf-16-le", "utf-16-be"):
                try:
                    text = raw.decode(enc)
                except UnicodeDecodeError:
                    continue
                if "\x00" not in text:
                    return _SURROGATE.sub("\ufffd", text).strip()
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return _SURROGATE.sub("�", raw).strip()  # lone surrogates never reach a caller


_NO_WS = str.maketrans("", "", "\t\n\r")


def _ratio(text: str) -> float:
    if text and text.translate(_NO_WS).isprintable():  # common case at C speed
        return 1.0
    return sum(1 for c in text if c.isprintable() or c in "\t\n\r") / len(text) if text else 0.0


def _readable(text: str | None) -> bool:
    """Reads like text: reported to the caller."""
    return bool(text) and len(text) >= MIN_TEXT and bool(_LETTERS.search(text)) and _ratio(text) >= PRINTABLE_RATIO


def _intermediate(text: str | None) -> bool:
    """Not prose, but clean ASCII that may be another encoding layer (hex inside base64)."""
    return bool(text) and len(text) >= 8 and text.isascii() and _ratio(text) >= 0.98


CHUNK_OVERLAP = 1024  # a payload cut by a chunk boundary is whole in the next chunk


def _chunks(text: str):
    """Long decoded text as PER_RUN-sized pieces that overlap, so a payload anywhere
    in a huge run (not just its head or tail) is seen whole by a scanner."""
    if len(text) <= PER_RUN:
        yield text
        return
    step = PER_RUN - CHUNK_OVERLAP
    for i in range(0, len(text), step):
        yield text[i:i + PER_RUN]
        if i + PER_RUN >= len(text):
            break


def _b64(run: str):
    s = re.sub(r"\s", "", run).rstrip("=")
    for skip in range(4):  # a few stray leading chars ("x-<b64>") break alignment
        t = s[skip:]
        if len(t) % 4 == 1 or len(t) < 8:
            continue
        alt = b"-_" if ("-" in t or "_" in t) else None
        if alt and ("+" in t or "/" in t):
            continue
        try:
            data = base64.b64decode(t + "=" * (-len(t) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        text = _as_text(data[:PER_RUN])  # the offset test needs only a prefix
        if _readable(text) or _intermediate(text):  # a wrong offset decodes to noise: try the next
            return data
    return None


def _b64_wrapped(run: str):
    joined = re.sub(r"\s", "", run)
    if not re.search(r"[0-9+/]", joined):  # prose (words with spaces) is not wrapped base64
        return None
    return _b64(joined)


def _b32(run: str):
    s = run.rstrip("=").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _hex(run: str):
    s = re.sub(r"0x|\\x|[^0-9A-Fa-f]", "", run, flags=re.I)
    return bytes.fromhex(s) if len(s) % 2 == 0 else None


def _bin(run: str):
    groups = re.findall(r"[01]+", run.replace("0b", " "))
    bits = "".join(groups)
    widths = (7,) if groups and all(len(g) == 7 for g in groups) else (8, 7)
    for width in widths:
        for offset in range(width):  # a stray leading bit misaligns every byte
            b = bits[offset:]
            b = b[: len(b) - len(b) % width]
            if len(b) < 4 * width:
                break
            data = bytes(int(b[i:i + width], 2) for i in range(0, len(b), width))
            text = _as_text(data)
            if text and _readable(text):
                return data
    return None


def _a85(run: str):
    return base64.a85decode(run, adobe=True)


def _b85(run: str):
    if run.isalnum():  # plain words / base64 runs: base85 needs punctuation
        return None
    for cand in dict.fromkeys((run, run.strip("()[]{}<>'\".,;:"), run.rstrip("()[]{}<>'\".,;:"))):
        for decode in (base64.b85decode, base64.a85decode):  # ascii85 without <~ ~> too
            try:
                data = decode(cand)
            except (ValueError, binascii.Error):
                continue
            if _readable(_as_text(data[:PER_RUN])):
                return data
    return None


def _a85_bare(run: str):
    if run.isalnum():
        return None
    return base64.a85decode(run.strip("()[]{}<>'\".,;:"), adobe=False)


def _morse(run: str):
    words = re.split(r"\s*/\s*| {3,}", run.strip())
    out = []
    for w in words:
        letters = [_MORSE_TABLE.get(code) for code in w.split()]
        if not letters or None in letters:
            return None
        out.append("".join(letters))
    return " ".join(out)


def _escapes(run: str):
    return codecs.decode(run, "unicode_escape")


def _tags(run: str):
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


_RUN_DECODERS = (
    ("binary", _BIN, _bin),
    ("hex", _HEX_SEPARATED, _hex),
    ("hex", _HEX, _hex),
    ("base32", _B32, _b32),
    ("base64", _B64, _b64),
    ("base64", _B64_WRAPPED, _b64_wrapped),
    ("ascii85", _A85, _a85),
    ("base85", _B85, _b85),
    ("ascii85", _A85_BARE, _a85_bare),
    ("morse", _MORSE, _morse),
    ("escape", _ESCAPES, _escapes),
    ("tags", _TAGS, _tags),
)


def _text_views(text: str) -> list[Decoded]:
    """Escapes mixed into ordinary words ("ign%6fre", "ignore"): decode the
    whole text, but only when it actually contains such an escape."""
    out = []
    if _PCT_ONE.search(text):
        try:
            out.append(Decoded("percent", urllib.parse.unquote(_PCT_GAP.sub(r"\1", text), errors="strict")))
        except UnicodeDecodeError:
            pass
    if _ESC_ONE.search(text):
        def one(m):
            try:
                return codecs.decode(m.group(0), "unicode_escape")
            except UnicodeDecodeError:
                return m.group(0)
        out.append(Decoded("escape", _ESC_ONE.sub(one, text)))
    return out


def _transforms(text: str) -> list[Decoded]:
    out = [Decoded("rot13", codecs.decode(text, "rot13")),
           Decoded("reversed", text[::-1])]
    leet = text.translate(_LEET)
    if leet != text:
        out.append(Decoded("leet", leet))
    spaced = _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), text)
    if spaced != text:
        spaced = re.sub(r"[ \t]{2,}", " ", spaced)  # the word gaps (2+ spaces) become one
        out.append(Decoded("spaced", spaced))
    return out


def variants(text: str, *, transforms: bool = False, max_depth: int = 2) -> list[Decoded]:
    """Every decoded view of `text`, deduplicated, in a stable order. `[]` when
    nothing decodes. `transforms=True` adds the whole-text rewrites."""
    if not isinstance(text, str) or not text:
        return []
    budget = MAX_OUTPUT
    seen = {text}
    out: list[Decoded] = []

    def emit(d: Decoded) -> None:
        nonlocal budget
        if budget > 0 and d.text not in seen and _readable(d.text):
            seen.add(d.text)
            budget -= len(d.text)
            out.append(d)

    tried: set[tuple[str, str]] = set()  # (decoder, run): identical runs decode once
    frontier = [Decoded("", text)]
    for _depth in range(max(1, max_depth)):
        nxt: list[Decoded] = []
        for item in frontier:
            for name, rx, decode in _RUN_DECODERS:
                if budget <= 0:
                    break
                for m in rx.finditer(item.text):
                    run = m.group(0)
                    key = (name, run)
                    if key in tried:
                        continue
                    tried.add(key)
                    try:
                        decoded = _as_text(decode(run))
                    except (ValueError, binascii.Error, UnicodeDecodeError, OverflowError):
                        continue
                    if not decoded or decoded == run.strip():
                        continue
                    label = f"{item.encoding}>{name}" if item.encoding else name
                    for piece in _chunks(decoded):
                        d = Decoded(label, piece)
                        emit(d)
                        if _readable(piece) or _intermediate(piece):
                            nxt.append(d)
                        if budget <= 0:
                            break
                    if budget <= 0:
                        break
        frontier = nxt
        if not frontier:
            break
    for d in _text_views(text):
        emit(d)
    if transforms:
        for d in _transforms(text):
            emit(d)
    return out
