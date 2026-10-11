"""Bounded structural validation of private supporting images, without rendering them.

Image content still needs explicit human sanitization review. These checks reject mislabeled
text/archives and damaged containers; they do not infer that a screenshot is free of secrets.
"""

import zlib

from .models import require


def png(raw):
    """Validate exact PNG chunk boundaries, checksums and mandatory container structure."""
    require(raw.startswith(b"\x89PNG\r\n\x1a\n"))
    offset = 8
    seen_header = seen_data = False
    count = 0
    while offset < len(raw):
        count += 1
        require(count <= 10000 and offset + 12 <= len(raw))
        size = int.from_bytes(raw[offset : offset + 4], "big")
        kind = raw[offset + 4 : offset + 8]
        require(size <= len(raw) - offset - 12)
        chunk = raw[offset + 4 : offset + 8 + size]
        require(
            zlib.crc32(chunk) == int.from_bytes(raw[offset + 8 + size : offset + 12 + size], "big")
        )
        if not seen_header:
            require(kind == b"IHDR" and size == 13)
            require(
                int.from_bytes(raw[offset + 8 : offset + 12], "big") > 0
                and int.from_bytes(raw[offset + 12 : offset + 16], "big") > 0
            )
            seen_header = True
        elif kind == b"IHDR":
            require(False)
        elif kind == b"IDAT":
            seen_data = True
        offset += size + 12
        if kind == b"IEND":
            require(size == 0 and seen_header and seen_data and offset == len(raw))
            return
    require(False)


def jpeg(raw):
    """Verify bounded JPEG segment/scan framing and reject bytes beyond its final marker."""
    require(raw.startswith(b"\xff\xd8"))
    offset = 2
    frame = scan = False
    while offset < len(raw):
        require(raw[offset] == 255 and offset + 1 < len(raw))
        while offset < len(raw) and raw[offset] == 255:
            offset += 1
        require(offset < len(raw))
        marker = raw[offset]
        offset += 1
        if marker == 217:
            require(frame and scan and offset == len(raw))
            return
        require(marker not in {0, 216} and not 208 <= marker <= 215 and offset + 2 <= len(raw))
        size = int.from_bytes(raw[offset : offset + 2], "big")
        require(size >= 2 and offset + size <= len(raw))
        if marker in {192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207}:
            require(size >= 8)
            frame = True
        offset += size
        if marker == 218:
            require(frame)
            scan = True
            while offset < len(raw):
                if raw[offset] != 255:
                    offset += 1
                elif offset + 1 < len(raw) and (
                    raw[offset + 1] == 0 or 208 <= raw[offset + 1] <= 215
                ):
                    offset += 2
                else:
                    break
    require(False)
