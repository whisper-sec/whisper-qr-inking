"""TLD morph sweep: which same-length real TLDs are a cheap QR-Inking edit apart.

For two URLs https://<sld>.<tldA> and https://<sld>.<tldB> of the same length,
the two QR codewords differ only in the TLD byte positions, so the module cost
of morphing one into the other is a property of (len(sld), tldA, tldB), not of
the SLD content. This script measures that cost for every same-length real-TLD
pair, and ranks TLDs by how many other real TLDs sit within k modules (the hub
= the most exposed TLD).

Cost is polarity "any" (attacker may add or remove ink): the user-module count
plan_attack() returns, computed straight from the block structure.
"""
import sys, os, json, argparse
from collections import defaultdict

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, SRC)
from qr_domain_flip import popcount, data_codewords, protect  # noqa: E402

LEVEL = "M"
MAXMOD = 3  # keep edges up to this many modules


def fits(url, version, level=LEVEL):
    try:
        data_codewords(url, version, level); return True
    except Exception:
        return False


def smallest_version(url, level=LEVEL):
    for v in range(1, 10):
        if fits(url, v, level):
            return v
    return None


def blocks_of(url, version, level=LEVEL):
    return protect(data_codewords(url, version, level), version, level)


def cost(bA, bB):
    """(user_modules, symbol_distance, minimum_weight) for polarity 'any', or None."""
    total_user = 0; total_dist = 0; minw = True
    for x, y in zip(bA, bB):
        cw1 = x["data"] + x["parity"]; cw2 = y["data"] + y["parity"]
        w = [popcount(a ^ c) for a, c in zip(cw1, cw2) if a != c]
        d = len(w)
        if d == 0:
            continue
        total_dist += d
        t = x["nsym"] // 2
        user_n = d - 2 * t
        if user_n < 1:
            return None
        w.sort()
        total_user += sum(w[:user_n])
        if d != x["nsym"] + 1:
            minw = False
    return (total_user, total_dist, minw)


def load_tlds(path):
    d = json.load(open(path))
    return sorted(set(t for t in d["tlds"] if t.isascii() and t.isalpha()))


def sweep(tlds, sld, level=LEVEL):
    sample = f"https://{sld}.{tlds[0]}"
    version = smallest_version(sample, level)
    blk = {}
    for t in tlds:
        try:
            blk[t] = blocks_of(f"https://{sld}.{t}", version, level)
        except Exception:
            pass
    tl = [t for t in tlds if t in blk]
    adj = defaultdict(list)   # tld -> [(partner, modules)]
    for i in range(len(tl)):
        for j in range(i + 1, len(tl)):
            a, b = tl[i], tl[j]
            c = cost(blk[a], blk[b])
            if c is None:
                continue
            m = c[0]
            if m <= MAXMOD:
                adj[a].append((b, m)); adj[b].append((a, m))
    return version, len(tl), adj


def deg(adj, t, k):
    return sum(1 for _, m in adj.get(t, []) if m <= k)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tlds", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    by_len = defaultdict(list)
    for t in load_tlds(args.tlds):
        by_len[len(t)].append(t)
    for L in by_len:
        by_len[L] = sorted(by_len[L])

    print("# content-independence check: cost depends on SLD length, not SLD content")
    v = smallest_version("https://google.com")
    ok = True
    for a, b in [("com", "cam"), ("com", "net"), ("org", "ong"), ("net", "pet")]:
        ca = cost(blocks_of(f"https://google.{a}", v), blocks_of(f"https://google.{b}", v))
        cb = cost(blocks_of(f"https://abydos.{a}", v), blocks_of(f"https://abydos.{b}", v))
        same = ca == cb
        ok &= same
        print(f"  {a}->{b}: google.*={ca}  abydos.*={cb}  identical={same}")
    print(f"  => content-independent at fixed SLD length: {ok}\n")

    dump = {}
    for tld_len, slds in [(2, ["kaveh"]), (3, ["kaveh", "google"])]:
        tlds = by_len.get(tld_len, [])
        print(f"{'='*72}\n# TLD length {tld_len}: {len(tlds)} real alpha TLDs")
        for sld in slds:
            version, n, adj = sweep(tlds, sld)
            e1 = sum(1 for t in adj for p, m in adj[t] if m == 1) // 2
            e2 = sum(1 for t in adj for p, m in adj[t] if m == 2) // 2
            e3 = sum(1 for t in adj for p, m in adj[t] if m == 3) // 2
            print(f"\n## sld='{sld}' len{len(sld)}  ->  version {version}-{LEVEL}, {n} TLDs encoded")
            print(f"   cheap pairs: 1-module={e1}  2-module={e2}  3-module={e3}")
            hubs = sorted(adj.keys(), key=lambda t: (-deg(adj, t, 2), -deg(adj, t, 3)))[:12]
            print("   most exposed TLDs (count of other real TLDs within k modules):")
            print(f"     {'TLD':<6} <=1  <=2  <=3   nearest (modules)")
            for t in hubs:
                near = sorted(adj[t], key=lambda pm: (pm[1], pm[0]))[:8]
                ns = ", ".join(f"{p}:{m}" for p, m in near)
                print(f"     .{t:<5}{deg(adj,t,1):>4} {deg(adj,t,2):>4} {deg(adj,t,3):>4}   {ns}")
            dump[f"{sld}.{tld_len}"] = {
                "version": f"{version}-{LEVEL}", "tlds": n,
                "pairs": {"m1": e1, "m2": e2, "m3": e3},
                "exposed": {t: sorted(adj[t], key=lambda pm: pm[1]) for t in adj},
            }
        print()

    print(f"{'='*72}\n# README example morphs (sorted by modules)")
    for sld, tld in [("kaveh", "org"), ("google", "com")]:
        tlds = by_len[len(tld)]
        version, n, adj = sweep(tlds, sld)
        near = sorted(adj.get(tld, []), key=lambda pm: (pm[1], pm[0]))
        print(f"\n## {sld}.{tld} (v{version}-{LEVEL}): cheapest real-TLD morphs")
        print("   " + ", ".join(f"{sld}.{p} ({m} mod)" for p, m in near[:20]))

    if args.out:
        json.dump(dump, open(args.out, "w"), indent=1)
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
