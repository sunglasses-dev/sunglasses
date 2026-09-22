"""Render a regex source into one plausible matching string.

Not a regex engine and not trying to be: it walks the source and emits the
FIRST alternative of every choice, one representative character per class, and
a space for any whitespace or wildcard run. Good enough to produce text a rule
was written to match, which is all a probe corpus needs.
"""
import re

_FLAGS = re.compile(r"^\(\?[aiLmsux]+\)")

def sample(src, depth=0):
    if depth > 12:
        return ""
    src = _FLAGS.sub("", src)
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            nxt = src[i+1] if i+1 < n else ""
            if nxt in "sS":
                out.append(" "); i += 2
            elif nxt in "dD":
                out.append("7"); i += 2
            elif nxt in "wW":
                out.append("a"); i += 2
            elif nxt == "b":
                i += 2
            elif nxt == "n":
                out.append("\n"); i += 2
            elif nxt == "r":
                out.append("\r"); i += 2
            elif nxt == "t":
                out.append("\t"); i += 2
            elif nxt == "u" and i+6 <= n:
                try: out.append(chr(int(src[i+2:i+6], 16)))
                except ValueError: pass
                i += 6
            else:
                out.append(nxt); i += 2
            continue
        if c == "[":
            j, esc, cls = i+1, False, []
            while j < n:
                if esc: esc = False; cls.append(src[j])
                elif src[j] == "\\": esc = True
                elif src[j] == "]": break
                else: cls.append(src[j])
                j += 1
            body = "".join(cls)
            if body.startswith("^"):
                out.append("a")
            else:
                m = re.search(r"[A-Za-z0-9]", body)
                out.append(m.group(0) if m else (body[0] if body else "a"))
            i = j + 1
            continue
        if c == "(":
            # find the matching close
            j, d, esc, incls = i, 0, False, False
            while j < n:
                ch = src[j]
                if esc: esc = False
                elif ch == "\\": esc = True
                elif ch == "[": incls = True
                elif ch == "]": incls = False
                elif not incls and ch == "(": d += 1
                elif not incls and ch == ")":
                    d -= 1
                    if d == 0: break
                j += 1
            inner = src[i+1:j]
            for pre in ("?:", "?i:", "?-i:", "?s:", "?is:"):
                if inner.startswith(pre): inner = inner[len(pre):]; break
            else:
                if inner[:2] in ("?=", "?!") or inner[:3] in ("?<=", "?<!"):
                    inner = "" if inner[:2] == "?!" or inner[:3] == "?<!" else inner[2:]
                elif inner.startswith("?P<"):
                    inner = inner[inner.index(">")+1:]
            # first alternative at depth 0
            alt, d2, esc2, incls2, cut = [], 0, False, False, None
            for k, ch in enumerate(inner):
                if esc2: esc2 = False
                elif ch == "\\": esc2 = True
                elif ch == "[": incls2 = True
                elif ch == "]": incls2 = False
                elif not incls2 and ch == "(": d2 += 1
                elif not incls2 and ch == ")": d2 -= 1
                elif not incls2 and ch == "|" and d2 == 0: cut = k; break
            inner = inner[:cut] if cut is not None else inner
            out.append(sample(inner, depth+1))
            i = j + 1
            continue
        if c in ".":
            out.append(" "); i += 1; continue
        if c in "^$":
            i += 1; continue
        if c in "*?":
            i += 1; continue
        if c == "+":
            i += 1; continue
        if c == "{":
            j = src.find("}", i)
            i = (j + 1) if j != -1 else i + 1
            continue
        if c == "|":
            break
        out.append(c); i += 1
    return "".join(out)
