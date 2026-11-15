# One module, different host

Superseded as a write-up by [qr-inking.pdf](../paper/qr-inking.pdf). That paper adds directed edits (add ink or remove ink) and the top-n ranking. This file is the earlier measurement note. The implementation is `qr_domain_flip.py`.

## Result

A stock QR code for a URL is not one dot away from a different host. Two same-length URLs are Reed-Solomon codewords at least \(d_{\min} = n_{\mathrm{ec}}+1\) symbols apart. On version 2, level M, `https://google.com` and `https://googlg.com` differ in 17 symbols and 54 modules. Flipping the lightest 8 of those symbols (18 modules) still decodes as `google.com`. The 9th symbol, 21 modules in all, is what finally returns `googlg.com`. One dot on a code that came out of a normal generator does nothing.

The one-dot attack is an attack on a different symbol: one that already contains \(t = \lfloor n_{\mathrm{ec}}/2 \rfloor\) symbol errors toward the attacker's codeword and still decodes as the real host. Flipping the one remaining symbol switches the decoder. For `google.com` → `googlg.com` at version 2-M, mask 0, that symbol is a single module at `(15, 15)`, and that module is a bit of the host character that actually changed. The same shape holds for version 2-L, 2-Q, 2-H, 3-M, 3-Q, 3-H, 4-L, 4-M, 5-L, 5-M, 5-Q and 6-M. It does not hold for version 1-L or 3-L, where \(n_{\mathrm{ec}}\) is odd and the minimum user edit is two symbols.

Changing the length of the string, including a TLD swap or inserting a dot in the name, is a different distance and is not this attack.

## Algorithm

Input: URL \(A\), URL \(B\) of the same byte length, version, level, mask. Both must fit that symbol in byte mode.

1. Encode both as byte mode. Versions 1-9: 4-bit mode `0100`, 8-bit character count, then the raw bytes. Terminator, pad bits to a codeword boundary, then pad codewords `11101100` / `00010001` up to the data capacity.
2. Split the data codewords into the ISO block structure for that version and level and append the Reed-Solomon parity of each block. Blocks are independent codes. \(d_{\min} = n_{\mathrm{ec}}+1\) per block, \(t = \lfloor n_{\mathrm{ec}}/2 \rfloor\).
3. In each block let \(D\) be the symbols where the two codewords differ. Skip blocks with \(D\) empty. Reject the pair if any block has \(|D| - 2t < 1\) (this does not happen for two distinct RS codewords at this \(t\)).
4. User set \(U\): the \(|D|-2t\) lightest symbols of \(D\), ties broken toward a symbol whose data codeword overlaps the hostname, then toward the lower index. To force the dot into the domain, put the lightest hostname symbol of that block into \(U\) first and fill the rest of the budget with the lightest remaining symbols.
5. Preload \(P\): any \(t\) symbols of \(D \setminus U\). The rest of \(D\) is left equal to \(A\). The implementation takes the lowest indexes. Any other \(t\)-subset is the same attack; only \(U\) determines the modules the user has to flip.
6. Place \(A\) (interleave data round-robin, then parity round-robin, ISO 7.6; zigzag placement ISO 7.7.3; apply the mask; write format and version). Invert the modules of \(P\). That is the printed symbol.
7. The user modules are the bits set in each symbol of \(U\), MSB first, at bitstream index \(8 \cdot s + b\) where \(s\) is that symbol's index in the interleaved stream. Inverting a module inverts the bit either way, masked or not.
8. Check. Distance from the printed symbol to \(A\) is \(t\), so a decoder of radius \(t\) returns \(A\). After \(U\) is inverted, distance to \(B\) is \(t\) and distance to \(A\) is \(|D|-t > t\), so it returns \(B\). On a minimum-weight block with even \(n_{\mathrm{ec}}\), \(|D| = 2t+1\) and \(U\) is one symbol. If that symbol has popcount 1, the user action is one module.

Hostname codewords, versions 1-9: the host occupies payload characters \([s, e)\), which are bitstream bits \([12+8s,\ 12+8e)\). Every character straddles two data codewords because the header is 12 bits. A module of a "host codeword" is a host character only when the flipped bit itself falls in that range. In this sweep, every one-module host-constrained edit was a bit of the edited character, not the neighbouring nibble.

If a scanner rejects the printed symbol, keep \(U\) and draw a different \(t\)-subset for \(P\) (`search_preload`). The user coordinates do not move. Reed-Solomon accepts every such subset. Detectors do not.

## What was decoded

`qr_domain_flip.py --check`. "Boundary" is the printed symbol. "After the flip" inverts only the user modules. "Stock + that dot" inverts those same modules on a normal symbol for \(A\).

| From | To | Symbol | User modules | Boundary | After the flip | Stock + that dot |
|---|---|---|---|---|---|---|
| `https://google.com` | `https://googlg.com` | 2-M, 1 block | `(15,15)` char 13 | google.com | googlg.com | google.com |
| `https://google.com` | `https://coogle.com` | 2-M, 1 block | `(11,19)` char 8 | google.com | coogle.com | google.com |
| `https://apple.com` | `https://applu.com` | 2-L, 1 block | `(23,15)` char 12 | apple.com | applu.com | apple.com |
| `https://example.com` | `https://example1com` | 3-M, 1 block | `(26,21)` char 15 | example.com | example1com | example.com |
| `https://google.com` | `https://ggogle.com` | 5-L, 1 block | `(25,34)` char 9 | google.com | ggogle.com | google.com |
| `https://google.com` | `https://gokgle.com` | 4-M, 2 blocks | `(19,24)` | google.com | gokgle.com | google.com |
| `https://google.com` | `https://google.cox` | 5-Q, 4 blocks | `(36,33)` | google.com | google.cox | google.com |
| `https://google.com` | `https://googne.com` | 6-M, 4 blocks | `(11,27)` | google.com | googne.com | google.com |
| `https://example.com` | `https://example.c-m` | 3-Q, 2 blocks | `(14,27)` | example.com | example.c-m | example.com |
| `https://a.co` | `https://q.co` | 1-M, 1 block | `(12,13)` | a.co | q.co | a.co |
| `https://google.com` | `https://google.som` | 3-L, 1 block | `(26,21)`, `(19,8)` | google.com | google.som | google.com |
| `https://google.com` | `https://goofle.com` | 2-L, ISO radius 4 | 3 modules | google.com | goofle.com | google.com |

Version 2-M is the symbol a default generator emits for `https://google.com`: it does not fit version 1, and level M is the usual default. Symbol distance 17, radius 8, 8 symbols preloaded, one user module inside the host.

The renderer was checked against segno at masks other than 0, including every level of version 2 that the URL fits, versions 3-Q and 3-H (2 blocks), 4-M (2 blocks), 5-Q (4 blocks of unequal data length) and 6-M (4 blocks). Module difference was 0 and the byte-mode payload extracted back out of the data codewords was the original URL.

## How often one module is enough

Every one-character substitution of the host over `a-z`, `0-9` and `-`. User symbol forced into a hostname codeword. Version 2-M, `https://google.com`, 361 edits:

| | count |
|---|---|
| symbol distance 17 (minimum) | 152 |
| symbol distance 18 | 209 |
| some symbol of weight 1, anywhere | 261 |
| some hostname symbol of weight 1 | 190 |
| one user module if parity is allowed | 95 |
| one user module inside the hostname | 51 |

So 51 of 361 edits, all of them minimum weight, are a single hostname module once the symbol sits on the boundary. 44 further edits are a single module too, but that module is parity, not the domain. The other 139 edits that do contain a weight-1 hostname symbol still need a second symbol, because the block distance is 18 and \(|U| = |D|-2t = 2\).

The same count of one-module host edits on the other brands at version 2-M: apple.com 52/325, example.com 62/397, paypal.com 52/361, amazon.com 48/361, github.com 52/361, a.co 21/145. Across versions 2-L through 6-M the best same-length edit of each of those hosts was one module, except version 1-L and version 3-L.

Version 3-L has 15 error-correction symbols, so \(t = 7\) and \(d_{\min} = 16 = 2t+2\). Minimum weight still leaves two user symbols. The best `google.com` edit there is two modules, `(26,21)` and `(19,8)`, and both decoders returned `google.som` only after both were flipped. Version 1-L is the same shape (\(n_{\mathrm{ec}} = 7\), \(t = 3\), two user modules).

ISO/IEC 18004 holds back \(p = 2\) syndromes on version 2-L, so a strict reading of the standard corrects 4 errors, not 5. At radius 4 the best `google.com` edit needs three modules, `(24, 17)`, `(12, 7)` and `(9, 0)`, not one. Only the first of those is a host character. OpenCV does not hold those syndromes back: at radius 5 the same family of edits is one module, and OpenCV decoded it. The CLI flag `--iso` selects the smaller radius.

When a one-character edit lands on a block boundary, two blocks differ and each contributes a user symbol. On version 3-Q, 20 of 361 edits of `google.com` have symbol distance 38, which is \(d_{\min}\) in both blocks. `google.com` → `google.qom` flips the `c` (payload character 15). That character straddles the two blocks, so the user edit is two host modules, `(20, 16)` and `(23, 28)`, one weight-1 symbol in each block. The boundary still decodes as `google.com`. Flipping both modules returns `google.qom`.

## Stock code, measured

Version 2-M, `google.com` → `googlg.com`, symbols ordered lightest first, flipped in full off the stock symbol:

| Symbols converted | Modules | Decodes as |
|---|---|---|
| 1 | 1 | google.com |
| 8 | 18 | google.com |
| 9 | 21 | googlg.com |

Nine is \(|D|-t\). Partial bit flips inside a symbol match neither codeword, so they are not a cheaper route to \(B\). The weight-1 symbol is real, and it is not sufficient on its own.

## Detectors

Reed-Solomon decoding of the codewords (not the image) accepted all 12 of 12 random preloads of the `googlg` pair: the boundary came back as \(A\) and the switched word as \(B\). OpenCV's current Aruco QR detector also accepted 20 of 20 random preloads, and 361 of 361 deterministic plans for the `google.com` version-2-M sweep, boundary and switched.

The older `cv2.QRCodeDetector` accepted 359 of those 361 plans and 10 of 12 random preloads. The two deterministic misses (`gfogle`, `gougle`) are two-module plans. A different preload of the same user symbols was accepted on 26 of 30 and 25 of 30 draws, and the user coordinates did not change. `search_preload` does that search. The one-module plans in the table above were accepted by both detectors with the default preload.

Mask does not change the module count. It changes coordinates. All numbers above are mask 0 unless the renderer check says otherwise.

## What to show

For a brand, at the version and level a normal generator would emit (and at 2-L, 2-M, 3-M, 4-L):

- the same-length host edit with the smallest user-module count, hostname symbol preferred
- version, level, mask, block count, symbol distance, radius
- the boundary symbol with the user modules marked, not a stock symbol with a dot drawn on it
- the string decoded before and after those modules
- whether the pair is minimum weight, and whether each user bit is a host character
- whether the resulting name is registered, which is WhisperGraph's job and is not answered here

The targets in the table are coding witnesses. `googlg` and `coogle` are not claimed to be registered, or to be visually confusable beyond the one-character edit.

## Detection

The printed symbol decodes as \(A\) and already has \(t\) corrected symbols, and those symbols are exactly a preload aimed at one neighbour \(B\).

- Flag a scan whose corrected-symbol count is \(t\) or \(t-1\). Ordinary damage is not concentrated on one neighbour's difference set.
- Invert each data module and decode again. A stock symbol stays on \(A\). A one-module boundary symbol has exactly one module that moves it to \(B\).
- Format information gives the level, so \(t\) is known.

This is the deterministic endpoint of the fake-QR construction of Takita, Okuma and Morii (CANDAR 2018). Ohigashi, Kawaguchi, Kobayashi et al. (2021) detect that family from the error-correction trace. The same trace catches this symbol, because a clean scan is already sitting on the radius.

## Reproduce

```
python3 qr_domain_flip.py https://google.com --check --png-dir qr_demo
python3 qr_domain_flip.py https://google.com --to https://coogle.com --check
python3 qr_domain_flip.py https://apple.com --version 2 --level L --check
python3 qr_domain_flip.py https://example.com --version 3 --level M --check
python3 qr_domain_flip.py https://google.com --version 5 --level L --check
python3 qr_domain_flip.py https://google.com --version 4 --level M --check
python3 qr_domain_flip.py https://google.com --version 2 --level L --iso --check
python3 qr_sweep.py
```

`qr_demo/intermediate.png` is the version-2-M boundary symbol for `https://google.com`, user module in red. `qr_demo/switched.png` is that symbol after the module is inverted.

## References

M. Takita, H. Okuma, M. Morii. A Construction of Fake QR Codes Based on Error-Correcting Codes. CANDAR 2018, pp. 188-193.

T. Ohigashi, S. Kawaguchi, K. Kobayashi, et al. Detecting Fake QR Codes Using Information from Error-Correction. Journal of Information Processing, vol. 29, pp. 548-558, 2021.

ISO/IEC 18004. Block structure, generator, and placement as implemented by segno 1.6.6.
