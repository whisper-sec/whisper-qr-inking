"""QR-Inking across the IANA root: which same-length TLDs morph into each other.

Two URLs https://<sld>.<A> and https://<sld>.<B> of the same length are
Reed-Solomon codewords that differ only in the TLD byte positions. The number
of QR modules an attacker must flip to turn a printed code for .A into one that
decodes .B is:

  - "any" polarity (add or remove ink): a property of (len(sld), A, B) only,
    NOT of the SLD text. Content-independent. This is the structural distance.
  - "darken" (add ink only) and "lighten" (remove ink only): directional, and
    they depend on the printed code (SLD text + mask), because whether a given
    module is currently light or dark is what decides add vs remove.

This tool measures all three over every TLD in the IANA root, grouped by length,
finds the most exposed TLDs (hubs), and surfaces the single-operation morphs
(e.g. ".com -> .net by adding N dots, nothing erased").

Reproduce: .venv/bin/python tld_research.py --tlds data/tlds-alpha-by-domain.txt --out out/tld-research.json
"""
import sys, os, json, argparse, itertools
from collections import defaultdict

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, SRC)
from qr_domain_flip import (  # noqa: E402
    popcount, data_codewords, protect, plan_attack, render, placement_map,
)

LEVEL = "M"


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


def any_cost(bA, bB):
    """Minimum user modules, polarity 'any' (parity modules allowed). None if not a boundary pair."""
    total = 0; minw = True
    for x, y in zip(bA, bB):
        cw1 = x["data"] + x["parity"]; cw2 = y["data"] + y["parity"]
        w = sorted(popcount(a ^ c) for a, c in zip(cw1, cw2) if a != c)
        d = len(w)
        if d == 0:
            continue
        t = x["nsym"] // 2
        un = d - 2 * t
        if un < 1:
            return None
        total += sum(w[:un])
        if d != x["nsym"] + 1:
            minw = False
    return total


def load_iana(path):
    out = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.lower())
    return sorted(set(out))


def deg(adj, t, k):
    return sum(1 for _, m in adj.get(t, []) if m <= k)


def hub_table(adj, title, kmax=3, topn=15):
    print(f"   {title}")
    print(f"     {'TLD':<7} <=1  <=2  <=3   nearest (modules)")
    hubs = sorted(adj.keys(), key=lambda t: tuple(-deg(adj, t, k) for k in (1, 2, 3)))[:topn]
    for t in hubs:
        near = sorted(adj[t], key=lambda pm: (pm[1], pm[0]))[:10]
        ns = ", ".join(f"{p}:{m}" for p, m in near)
        print(f"     .{t:<6}{deg(adj,t,1):>4} {deg(adj,t,2):>4} {deg(adj,t,3):>4}   {ns}")


def run_any(tlds, sld):
    """Undirected any-polarity map for a length class at a fixed SLD length."""
    version = smallest_version(f"https://{sld}.{tlds[0]}")
    blk = {}
    for t in tlds:
        try:
            blk[t] = blocks_of(f"https://{sld}.{t}", version)
        except Exception:
            pass
    tl = [t for t in tlds if t in blk]
    adj = defaultdict(list)
    for a, b in itertools.combinations(tl, 2):
        m = any_cost(blk[a], blk[b])
        if m is not None and m <= 3:
            adj[a].append((b, m)); adj[b].append((a, m))
    return version, len(tl), adj


def run_polarity(tlds, sld, mask=0, cap=6):
    """Directional darken (add ink) map: print .A, add dots -> decodes .B. SLD/mask specific."""
    version = smallest_version(f"https://{sld}.{tlds[0]}")
    places = placement_map(version)
    url = {}; blk = {}; clean = {}
    for t in tlds:
        u = f"https://{sld}.{t}"
        try:
            b = blocks_of(u, version)
        except Exception:
            continue
        url[t] = u; blk[t] = b; clean[t] = render(b, version, LEVEL, mask)
    tl = list(url)
    dark = defaultdict(list)   # A -> [(B, add-ink modules)]  print A, add dots, reads B
    light = defaultdict(list)  # A -> [(B, remove-ink modules)]
    for a in tl:
        for b in tl:
            if a == b:
                continue
            for pol, adj in (("darken", dark), ("lighten", light)):
                try:
                    p = plan_attack(url[a], url[b], version, LEVEL, mask,
                                    clean=clean[a], places=places, polarity=pol)
                except ValueError:
                    continue
                if p.user_modules <= cap:
                    adj[a].append((b, p.user_modules))
    return version, len(tl), dark, light


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tlds", required=True)
    ap.add_argument("--out")
    ap.add_argument("--polarity-classes", default="2,3,4")
    ap.add_argument("--polarity-sld", default="amazon")
    args = ap.parse_args()

    tlds = load_iana(args.tlds)
    by_len = defaultdict(list)
    for t in tlds:
        by_len[len(t)].append(t)
    print(f"# IANA root: {len(tlds)} TLDs; lengths present: {sorted(by_len)}")

    # content independence
    print("\n# content-independence (any-polarity module count depends on SLD length, not text)")
    v = smallest_version("https://google.com")
    allok = True
    for a, b in [("com", "cam"), ("com", "net"), ("org", "ong"), ("biz", "wiz")]:
        if b not in by_len[len(b)]:
            continue
        ca = any_cost(blocks_of(f"https://google.{a}", v), blocks_of(f"https://google.{b}", v))
        cb = any_cost(blocks_of(f"https://abydos.{a}", v), blocks_of(f"https://abydos.{b}", v))
        allok &= (ca == cb)
        print(f"  {a}->{b}: {ca} vs {cb}  same={ca==cb}")
    print(f"  => {allok}")

    dump = {"iana_version_line": open(args.tlds).readline().strip(), "classes": {}}

    print("\n# ANY-POLARITY structural exposure, by TLD length (SLD length 6 canonical)")
    for L in (2, 3, 4):
        version, n, adj = run_any(by_len[L], "amazon")
        e = {k: sum(1 for t in adj for _, m in adj[t] if m == k) // 2 for k in (1, 2, 3)}
        print(f"\n## length {L}: {n} TLDs, version {version}-{LEVEL}; "
              f"cheap pairs 1mod={e[1]} 2mod={e[2]} 3mod={e[3]}")
        hub_table(adj, "most exposed (any polarity, undirected):")
        dump["classes"][f"any.len{L}"] = {
            "version": f"{version}-{LEVEL}", "n": n, "pairs": e,
            "exposed": {t: sorted(adj[t], key=lambda pm: pm[1]) for t in adj},
        }

    print("\n# SINGLE-OPERATION morphs: print .A, ADD ink only -> reads .B")
    print(f"#   (SLD='{args.polarity_sld}' len{len(args.polarity_sld)}, mask 0; directional, instance-specific)")
    for L in [int(x) for x in args.polarity_classes.split(",")]:
        version, n, dark, light = run_polarity(by_len[L], args.polarity_sld)
        nd = sum(1 for a in dark for _, m in dark[a])
        nl = sum(1 for a in light for _, m in light[a])
        print(f"\n## length {L}: version {version}-{LEVEL}; "
              f"add-ink morphs (<=6)={nd}, remove-ink morphs (<=6)={nl}")
        # cheapest add-ink (darken) morphs overall
        alld = sorted(((m, a, b) for a in dark for b, m in dark[a]))[:18]
        print("   cheapest ADD-INK morphs (.A --add N dots--> .B):")
        for m, a, b in alld:
            print(f"     .{a} -> .{b}   add {m} dot{'s' if m!=1 else ''}")
        hub_table({a: dark[a] for a in dark}, "most exposed by ADD-INK (out-degree):", topn=10)
        dump["classes"][f"darken.len{L}"] = {
            "version": f"{version}-{LEVEL}", "sld": args.polarity_sld, "mask": 0,
            "morphs": {a: sorted(dark[a], key=lambda pm: pm[1]) for a in dark},
        }
        dump["classes"][f"lighten.len{L}"] = {
            "morphs": {a: sorted(light[a], key=lambda pm: pm[1]) for a in light},
        }

    print("\n# NOTABLE legacy-gTLD pairs (sld='google' len6, mask 0)")
    notable = ["com", "net", "org", "biz", "edu", "gov", "mil", "int", "cat", "pro"]
    notable = [t for t in notable if t in by_len[3]]
    version = smallest_version("https://google.com")
    places = placement_map(version)
    cl = {t: render(blocks_of(f"https://google.{t}", version), version, LEVEL, 0) for t in notable}
    bl = {t: blocks_of(f"https://google.{t}", version) for t in notable}
    def pol(a, b, p):
        try:
            return plan_attack(f"https://google.{a}", f"https://google.{b}", version, LEVEL, 0,
                               clean=cl[a], places=places, polarity=p).user_modules
        except ValueError:
            return None
    npairs = {}
    print(f"   {'A -> B':<14} any   add(A->B)  remove(A->B)")
    for a, b in itertools.permutations(notable, 2):
        anym = any_cost(bl[a], bl[b])
        d = pol(a, b, "darken"); l = pol(a, b, "lighten")
        npairs[f"{a}->{b}"] = {"any": anym, "add": d, "remove": l}
        print(f"   .{a} -> .{b:<7} {str(anym):>3}   {str(d):>6}      {str(l):>6}")
    dump["notable_google"] = npairs

    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        json.dump(dump, open(args.out, "w"), indent=1)
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
