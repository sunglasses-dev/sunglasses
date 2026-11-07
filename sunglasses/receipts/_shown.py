"""How a diagnostic names a path somebody else may have named.

A path in an error line comes from a flag, a config file, an environment variable or a
directory another account made, so it can carry an escape sequence, a newline, a character
that prints as nothing, or bytes that are not text. `shown_path` is the one way a receipt
or key diagnostic writes such a path: shell-quoted when nothing is hidden in it, otherwise
between $'...' as byte escapes that bash (3.2 included) and zsh read back as the same bytes,
so the line stays one line and two different names never print the same. Several paths in
one message are each written this way and the message adds `ESCAPED_NOTE` once if any was
escaped. `printable` is for text that is not a path, and `shown_name` is for a name.

The producers that use it: the five key messages in `optin`, `_fs.Unlistable` (so a key or
hook-chain directory that cannot be listed names itself the same way in the proxy, the
command line and the hook), and the proxy's two startup refusals. It does not rewrite the
native text of an `OSError` raised elsewhere, which the signed-header failure keeps as it
was (cut at 200 characters).
"""
import os
import shlex

# Characters that print as nothing or as part of their neighbour, so a name using them
# can look like a different name. `str.isprintable()` rejects most of them (zero-width
# and bidi controls are "Format"); these are the default-ignorable ones it lets through.
_INVISIBLE = ((0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5),
              (0x180B, 0x180F), (0x2800, 0x2800), (0x3164, 0x3164),
              (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0), (0xE0100, 0xE01EF))


def _hidden(char):
    """True for a character a diagnostic must write out rather than print."""
    return (not char.isprintable()
            or any(low <= ord(char) <= high for low, high in _INVISIBLE))


def _escape(char):
    """`char` as the bytes it stands for, each written `\\xNN`, which bash (3.2 too)
    and zsh read inside `$'...'` as those bytes. A character is its UTF-8 bytes; a
    lone surrogate from `os.fsdecode` is the one non-UTF-8 byte it replaced."""
    code = ord(char)
    if 0xDC80 <= code <= 0xDCFF:
        raw = bytes([code - 0xDC00])
    else:
        raw = char.encode("utf-8", "surrogatepass")
    return "".join(f"\\x{byte:02x}" for byte in raw)


def printable(text):
    """`text` with every hidden character written out as an escape. For a message
    whose text is not a path (a path goes through `shown_path`, which also keeps two
    different names from printing the same). Output holds no terminal control character, and
    running it again changes nothing."""
    return "".join(_escape(c) if _hidden(c) else c for c in str(text))


def name_is_escaped(text):
    """True when `shown_name` writes `text` between $'...' (see there)."""
    text = str(text)
    return text.startswith("$'") or any(not (c.isprintable() or c == " ") for c in text)


def shown_name(text):
    """`text` as one line a person may read: a name somebody else chose (a tool, a server entry, a file).

    A name with nothing in it that `str.isprintable()` refuses comes back as it is, a backslash
    included (a Windows path is a name too). Any other name comes back between $'...': every
    refused character as an escape of fixed width (`\\xNN`, `\\uNNNN`, `\\UNNNNNNNN`; the space stays),
    a backslash and a quote each with a backslash in front. So the line holds no terminal control
    character, and a name that spells an escape out in plain text never prints the same as the
    name that holds the character: the first is shown as it is, the second between $'...'. A plain
    name that itself begins with $' is written between $'...' too, so the two never meet. Not for a
    path where a shell may read it back (that is `shown_path`) and not for a sentence that already
    holds escapes (that is `printable`)."""
    text = str(text)
    if not name_is_escaped(text):
        return text
    return "$'" + "".join(
        "\\\\" if ch == "\\" else "\\'" if ch == "'" else
        ch if (ch.isprintable() or ch == " ") else (
            f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else
            f"\\u{ord(ch):04x}" if ord(ch) < 0x10000 else f"\\U{ord(ch):08x}")
        for ch in text) + "'"


def shown_path(path):
    """(text, escaped): how a diagnostic names `path`, one way everywhere.

    A name with nothing hidden in it comes back shell-quoted, so the argument is
    exactly what a shell reads back (and a plain name is unchanged). One with a
    control or invisible character comes back between `$'...'` with those characters
    written as escapes and with `\\` and `'` escaped, so it is delimited, one line,
    and no other name prints the same. `escaped` tells the caller to say so."""
    text = os.fspath(path)
    if not any(_hidden(c) for c in text):
        return shlex.quote(text), False
    body = "".join("\\\\" if c == "\\" else "\\'" if c == "'" else
                   _escape(c) if _hidden(c) else c for c in text)
    return "$'" + body + "'", True


ESCAPED_NOTE = (" (the name has control or invisible characters, so it is written "
                "between $'...' as escapes)")
