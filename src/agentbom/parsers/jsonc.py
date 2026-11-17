from agentbom.parsers._shape import ShapeError


def strip_jsonc(text: str) -> str:
    """Remove comments and trailing commas, keeping line numbers intact."""
    out: list[str] = []
    last_token = -1
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j])
            last_token = len(out) - 1
            i = j
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ShapeError("invalid JSON: unterminated block comment")
            out.append("\n" * text.count("\n", i, end))
            i = end + 2
        else:
            if char in "]}" and last_token >= 0 and out[last_token] == ",":
                out[last_token] = " "
            out.append(char)
            if not char.isspace():
                last_token = len(out) - 1
            i += 1
    return "".join(out)
