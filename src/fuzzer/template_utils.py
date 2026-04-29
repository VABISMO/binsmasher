"""
Protocol-agnostic payload template utilities.

Handles {PAYLOAD} placeholder substitution and Content-Length recalculation.
Used by both UDP and HTTP exploit delivery.
"""
import re

PLACEHOLDER = b"{PAYLOAD}"


def find_inject_field(data: bytes) -> tuple[int, int, int]:
    """Find {PAYLOAD} position or longest repeated-byte run in data.

    Returns (start_offset, field_length, fill_byte).
    If {PAYLOAD} is found, returns (position, 4096, 0x41).
    If no placeholder, returns the longest run of >=16 identical bytes.
    """
    idx = data.find(PLACEHOLDER)
    if idx != -1:
        return idx, 4096, 0x41

    best_start, best_len, best_byte = 0, 0, 0x41
    i = 0
    while i < len(data):
        j = i + 1
        while j < len(data) and data[j] == data[i]:
            j += 1
        run_len = j - i
        if run_len >= 16 and run_len > best_len:
            best_start, best_len, best_byte = i, run_len, data[i]
        i = j
    return best_start, best_len, best_byte


def build_payload(template: bytes, inject: bytes) -> bytes:
    """Replace {PAYLOAD} or longest repeated-byte field with inject data.

    Auto-recalculates Content-Length headers if present.
    """
    if PLACEHOLDER in template:
        crafted = template.replace(PLACEHOLDER, inject, 1)
    else:
        best = None
        for m in re.finditer(rb"(.)\1{15,}", template):
            if best is None or len(m.group(0)) > len(best.group(0)):
                best = m
        if best:
            inj = (inject
                   + bytes([best.group(1)[0]]) * max(0, len(best.group(0)) - len(inject)))
            crafted = (template[:best.start()]
                       + inj[:len(best.group(0))]
                       + template[best.end():])
        else:
            crafted = template + inject

    sep = b"\r\n\r\n"
    if sep in crafted and b"Content-Length:" in crafted:
        hdr_part, body_part = crafted.split(sep, 1)
        body_len = len(body_part)
        new_hdr = re.sub(
            rb"(Content-Length:[ \t]*)\d+",
            lambda m: m.group(1) + str(body_len).encode(),
            hdr_part,
            flags=re.IGNORECASE,
        )
        crafted = new_hdr + sep + body_part
    return crafted