"""One-shot isolated parser; stdin is private, diagnostics never include source."""

import sys


def main():
    """Return only a bounded closed plan; reject any decoding or grammar failure."""
    from .models import QueryRequest
    from .sql import parse

    try:
        data = sys.stdin.buffer.read(16385)
        if len(data) > 16384:
            return 1
        result = parse(QueryRequest.model_validate_json(data)).model_dump_json().encode()
        if len(result) > 16384:
            return 1
        sys.stdout.buffer.write(result)
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
