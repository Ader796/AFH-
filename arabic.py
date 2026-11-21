"""Minimal Arabic shaping + visual reordering so Arabic renders correctly in PDF (reportlab has no shaping)."""
import re
import unicodedata

_FORMS = {}   # base char -> {'isolated','final','initial','medial'}
_LIG = {}     # (lam, alef-variant) -> {'isolated','final'}

for cp in range(0xFE70, 0xFEFD):
    ch = chr(cp)
    dec = unicodedata.decomposition(ch)
    if not dec.startswith("<"):
        continue
    parts = dec.split()
    kind = parts[0].strip("<>")
    base = [chr(int(x, 16)) for x in parts[1:]]
    if kind not in ("isolated", "final", "initial", "medial"):
        continue
    if len(base) == 1:
        _FORMS.setdefault(base[0], {})[kind] = ch
    elif len(base) == 2 and base[0] == "ل":
        _LIG.setdefault(tuple(base), {})[kind] = ch

_AR = re.compile(r"[؀-ۿݐ-ݿ]")
_TASHKEEL = re.compile(r"[ً-ٰٟ]")


def _joins_next(c):
    f = _FORMS.get(c)
    return bool(f and ("initial" in f))


def _joins_prev(c):
    f = _FORMS.get(c)
    return bool(f and ("final" in f))


def shape(text):
    text = _TASHKEEL.sub("", text)
    out, i, n = [], 0, len(text)
    chars = list(text)
    while i < n:
        c = chars[i]
        if c not in _FORMS:
            out.append(c); i += 1; continue
        prev = chars[i - 1] if i > 0 else ""
        prev_joins = bool(prev) and prev in _FORMS and _joins_next(prev) and not (out and out[-1] in ("\0",))
        # lam-alef ligature
        if c == "ل" and i + 1 < n and (c, chars[i + 1]) in _LIG:
            lig = _LIG[(c, chars[i + 1])]
            out.append(lig.get("final") if prev_joins and "final" in lig else lig["isolated"])
            i += 2
            continue
        nxt = chars[i + 1] if i + 1 < n else ""
        next_joins = bool(nxt) and nxt in _FORMS and _joins_prev(nxt) and _joins_next(c)
        f = _FORMS[c]
        if prev_joins and next_joins and "medial" in f:
            out.append(f["medial"])
        elif prev_joins and "final" in f:
            out.append(f["final"])
        elif next_joins and "initial" in f:
            out.append(f["initial"])
        else:
            out.append(f.get("isolated", c))
        i += 1
    return "".join(out)


def visual(text):
    """Shape and reorder a logical string for left-to-right rendering engines."""
    if not text or not _AR.search(text):
        return text
    s = shape(text)
    runs, cur, cur_rtl = [], "", None
    for ch in s:
        rtl = bool(_AR.match(ch)) or "ﭐ" <= ch <= "﻿"
        neutral = ch in " -_.,:;/()"
        if neutral and cur_rtl is not None:
            cur += ch
            continue
        if cur_rtl is None or rtl == cur_rtl:
            cur += ch; cur_rtl = rtl
        else:
            runs.append((cur, cur_rtl)); cur, cur_rtl = ch, rtl
    if cur:
        runs.append((cur, cur_rtl))
    # RTL paragraph: runs in reverse order, RTL runs reversed internally
    mirror = str.maketrans("()[]<>", ")(][><")
    return "".join(r[::-1].translate(mirror) if rtl else r for r, rtl in reversed(runs))
