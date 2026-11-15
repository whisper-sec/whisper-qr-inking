#!/usr/bin/env python3
"""Repeatable measurements for the boundary-QR host attack.

Run from anywhere:
    python3 /workspace/artifacts/qr_sweep.py
"""
from __future__ import annotations

import importlib.util
import random
import sys

import segno

spec = importlib.util.spec_from_file_location("qrflip", "/Users/kaveh/code/whisper/whisper-labs/publishing-collab/qr-boundary/src/qr_domain_flip.py")
q = importlib.util.module_from_spec(spec)
sys.modules["qrflip"] = q
spec.loader.exec_module(q)


def segno_matrix(url, version, level, mask):
    qr = segno.make(url, version=version, error=level.lower(), mask=mask, boost_error=False)
    return [[1 if c else 0 for c in row] for row in qr.matrix]


def payload_ok(url, version, level) -> bool:
    words = q.data_codewords(url, version, level)
    bits = []
    for w in words:
        for b in range(8):
            bits.append((w >> (7 - b)) & 1)
    chars = []
    for i in range(len(url)):
        val = 0
        for bit in bits[12 + 8 * i: 12 + 8 * i + 8]:
            val = (val << 1) | bit
        chars.append(chr(val))
    return "".join(chars) == url


def module_diff(a, b) -> int:
    return sum(x != y for r1, r2 in zip(a, b) for x, y in zip(r1, r2))


def check_renderer():
    print("== renderer vs segno ==")
    cases = [
        ("https://google.com", 2, "L", 0),
        ("https://google.com", 2, "M", 0),
        ("https://google.com", 2, "Q", 3),
        ("https://google.com", 2, "H", 5),
        ("https://example.com", 3, "L", 2),
        ("https://example.com", 3, "M", 1),
        ("https://example.com", 3, "Q", 4),
        ("https://example.com", 3, "H", 6),
        ("https://google.com", 4, "L", 4),
        ("https://google.com", 4, "M", 2),
        ("https://google.com", 5, "L", 5),
        ("https://google.com", 5, "Q", 1),
        ("https://google.com", 6, "M", 0),
        ("https://a.co", 1, "L", 0),
        ("https://a.co", 1, "M", 2),
        ("https://a.co", 1, "Q", 3),
        ("https://a.co", 1, "H", 7),
        ("https://apple.com", 1, "L", 1),
    ]
    bad = 0
    for url, v, lvl, mask in cases:
        try:
            blocks = q.protect(q.data_codewords(url, v, lvl), v, lvl)
        except ValueError as e:
            print(f"  skip {v}-{lvl} {url}: {e}")
            continue
        ours = q.render(blocks, v, lvl, mask)
        theirs = segno_matrix(url, v, lvl, mask)
        diff = module_diff(ours, theirs) if len(ours) == len(theirs) else -1
        ok_payload = payload_ok(url, v, lvl)
        status = "OK" if diff == 0 and ok_payload else "FAIL"
        if status != "OK":
            bad += 1
        print(f"  {status} diff={diff} payload={ok_payload} blocks={len(blocks)} {v}-{lvl} mask {mask} {url}")
    return bad


def sweep():
    print("== single-character sweep (host-constrained user symbol) ==")
    urls = [
        "https://google.com",
        "https://apple.com",
        "https://example.com",
        "https://paypal.com",
        "https://amazon.com",
        "https://github.com",
        "https://a.co",
    ]
    configs = [
        (1, "L"), (1, "M"), (1, "Q"), (1, "H"),
        (2, "L"), (2, "M"), (2, "Q"), (2, "H"),
        (3, "L"), (3, "M"), (3, "Q"), (3, "H"),
        (4, "L"), (4, "M"),
        (5, "L"), (5, "M"),
        (6, "M"),
    ]
    rows = []
    for url in urls:
        for v, lvl in configs:
            try:
                q.data_codewords(url, v, lvl)
            except ValueError:
                continue
            start, end = q.host_span(url)
            host = url[start:end]
            n = 0
            hist = {}
            one = 0
            one_host = 0
            one_charbit = 0
            best = None
            for i, ch in enumerate(host):
                for rep in q.ALPHABET:
                    if rep == ch:
                        continue
                    cand = url[: start + i] + rep + url[start + i + 1 :]
                    try:
                        plan = q.plan_attack(url, cand, v, lvl, 0, require_host_module=True)
                    except (ValueError, NotImplementedError):
                        continue
                    n += 1
                    hist[plan.symbol_distance] = hist.get(plan.symbol_distance, 0) + 1
                    if plan.user_modules == 1:
                        one += 1
                        if plan.user_in_host:
                            one_host += 1
                        chars = q.user_bit_characters(plan)
                        hs, he = q.host_span(url)
                        if chars and chars[0] is not None and hs <= chars[0] < he:
                            one_charbit += 1
                    key = (plan.user_modules, 0 if plan.user_in_host else 1, plan.bit_distance)
                    if best is None or key < best[0]:
                        best = (key, plan)
            if n == 0:
                continue
            bp = best[1]
            hist_s = ",".join(f"{k}:{hist[k]}" for k in sorted(hist))
            print(
                f"  {v}-{lvl} {url} n={n} dist[{hist_s}] "
                f"1mod={one} 1mod_hostcw={one_host} 1mod_hostchar={one_charbit} "
                f"best={bp.user_modules}mod {bp.url_to} mw={bp.minimum_weight} blocks={bp.blocks}"
            )
            rows.append((url, v, lvl, n, one, one_host, one_charbit, bp))
    return rows


def decode_case(label, plan):
    mats = q.matrices(plan)
    only = q.apply_symbols(mats["clean"], plan.version, plan.user_symbols)
    clean = q.decode_matrix(mats["clean"])
    boundary = q.decode_matrix(mats["intermediate"])
    switched = q.decode_matrix(mats["switched"])
    stock = q.decode_matrix(only)
    ok = clean == plan.url_from and boundary == plan.url_from and switched == plan.url_to and stock == plan.url_from
    coords = q.user_coordinates(plan)
    chars = q.user_bit_characters(plan)
    print(
        f"  {'OK' if ok else 'FAIL'} {label}: {plan.url_from} -> {plan.url_to} "
        f"{plan.version}-{plan.level} blocks={plan.blocks} d={plan.symbol_distance} "
        f"t={plan.radius} pre={len(plan.pre_symbols)} user={plan.user_modules} {coords} chars={chars}"
    )
    print(f"      clean={clean} boundary={boundary} switched={switched} stock+dot={stock}")
    # geometry: bit distance equals segno module distance
    A = segno_matrix(plan.url_from, plan.version, plan.level, plan.mask)
    B = segno_matrix(plan.url_to, plan.version, plan.level, plan.mask)
    md = module_diff(A, B)
    if md != plan.bit_distance:
        print(f"      GEOM FAIL module {md} != bits {plan.bit_distance}")
        ok = False
    return ok


def decoder_checks(rows):
    print("== decoder checks ==")
    bad = 0
    explicit = [
        ("google googlg 2-M", q.plan_attack("https://google.com", "https://googlg.com", 2, "M", 0)),
        ("google coogle 2-M", q.plan_attack("https://google.com", "https://coogle.com", 2, "M", 0)),
        ("apple applu 2-L", q.plan_attack("https://apple.com", "https://applu.com", 2, "L", 0)),
        ("example example1 3-M", q.plan_attack("https://example.com", "https://example1com", 3, "M", 0)),
        ("google ggogle 5-L", q.plan_attack("https://google.com", "https://ggogle.com", 5, "L", 0)),
        ("google iso 2-L", q.best_single_char("https://google.com", 2, "L", require_host_module=True, iso_conservative=True)),
        ("apple v1-L", q.best_single_char("https://apple.com", 1, "L", require_host_module=True)),
        ("a.co v1-M", q.best_single_char("https://a.co", 1, "M", require_host_module=True)),
        ("example v3-L", q.best_single_char("https://example.com", 3, "L", require_host_module=True)),
        ("example v3-Q", q.best_single_char("https://example.com", 3, "Q", require_host_module=True)),
        ("google v4-M", q.best_single_char("https://google.com", 4, "M", require_host_module=True)),
        ("google v5-Q", q.best_single_char("https://google.com", 5, "Q", require_host_module=True)),
        ("google v6-M", q.best_single_char("https://google.com", 6, "M", require_host_module=True)),
        ("paypal v2-H", q.best_single_char("https://paypal.com", 2, "H", require_host_module=False)),
    ]
    for label, plan in explicit:
        if plan is None:
            print(f"  SKIP {label}")
            continue
        if not decode_case(label, plan):
            bad += 1
    # one best plan per distinct (version, level) from the sweep, capped
    seen = set()
    for url, v, lvl, n, one, one_host, one_charbit, bp in rows:
        key = (v, lvl)
        if key in seen:
            continue
        seen.add(key)
        if not decode_case(f"best {v}-{lvl}", bp):
            bad += 1
    return bad


def random_partitions():
    print("== random preload partitions, v2-M google->googlg ==")
    url_a, url_b = "https://google.com", "https://googlg.com"
    b1, _b2, per = q.differences(url_a, url_b, 2, "M")
    diffs = per[0]
    t = 8
    d = len(diffs)
    user_n = d - 2 * t
    print(f"  d={d} t={t} user_n={user_n}")
    rng = random.Random(0)
    fails = 0
    trials = 12
    for trial in range(trials):
        order = diffs[:]
        rng.shuffle(order)
        user = sorted(order[:user_n], key=lambda s: s.index)
        rest = order[user_n:]
        rng.shuffle(rest)
        pre = rest[:t]
        # build plan-like matrices manually
        blocks = q.protect(q.data_codewords(url_a, 2, "M"), 2, "M")
        clean = q.render(blocks, 2, "M", 0)
        boundary = q.apply_symbols(clean, 2, pre)
        switched = q.apply_symbols(boundary, 2, user)
        db = q.decode_matrix(boundary)
        ds = q.decode_matrix(switched)
        ok = db == url_a and ds == url_b
        if not ok:
            fails += 1
        print(f"  trial {trial}: boundary={db} switched={ds} user_idx={[s.index for s in user]} {'OK' if ok else 'FAIL'}")
    return fails


def stock_lower_bound():
    print("== stock lower bound, lightest full symbols, v2-M google->googlg ==")
    url_a, url_b = "https://google.com", "https://googlg.com"
    _b1, _b2, per = q.differences(url_a, url_b, 2, "M")
    diffs = sorted(per[0], key=lambda s: (s.bits, s.index))
    t = 8
    need = len(diffs) - t
    blocks = q.protect(q.data_codewords(url_a, 2, "M"), 2, "M")
    clean = q.render(blocks, 2, "M", 0)
    for k in range(0, need + 1):
        flipped = q.apply_symbols(clean, 2, diffs[:k])
        got = q.decode_matrix(flipped)
        modules = sum(s.bits for s in diffs[:k])
        print(f"  symbols {k:2d}  modules {modules:3d}  -> {got}")
    return 0


def main():
    bad = check_renderer()
    rows = sweep()
    bad += decoder_checks(rows)
    bad += random_partitions()
    bad += stock_lower_bound()
    print(f"== failures: {bad} ==")
    return bad


if __name__ == "__main__":
    sys.exit(main())
