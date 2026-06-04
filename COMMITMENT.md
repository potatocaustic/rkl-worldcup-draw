# RKL "World Cup" Manager Draft — Draw Commitment

**Timestamp:** Published before the beacon round in section 3 below. The publication time is proven by this repository's commit history and the league-chat post of this file's SHA-256 (this line itself is not the proof).

This document fixes the entire draw procedure *before* the random seed is
generated. Because it is published before the seed exists, the commissioner
cannot have chosen a seed that produces a preferred result. Anyone can verify
the final order against the steps below.

---

## 1. The 48 managers (frozen)

Listed alphabetically for clarity. **The listing order has no effect on the
result** — the draw sorts every manager by a hash of their handle, so the order
they appear here cannot change anything.

```
_vinnie
aholl173
air&stinnybo
ak
benson
bigsnook
bohm
bos
burress
chargers
chars1
coop
corbin
det
domxb_06
dylan
fat
fears_
hairston
ja
jack
jamie
maliknabers.1
mason.rudolph
mclean
meth
minnesuffering
mmf
noahrawji
oli
ozone
plemay
prodraiders
reinhart13
risen
shabd
skiseason
snivy
snowy
soyel
tatismvpszn
thebigd0g
ur_mysunshine
valpo
walkemdowntohellandback
willi3
winn
woo
```

This exact list is the file `managers.txt` used in section 5.

---

## 2. The algorithm (frozen)

- Tool: `provably_fair_draw.py` (attached / linked: https://github.com/potatocaustic/rkl-worldcup-draw)
- **Script SHA-256:** `078f74ea805f1d1029062725a9fe4229f597e91cc2fe4ae539a32c51e762552f`
  - Confirm it yourself: `python3 provably_fair_draw.py self-hash`
  - If this hash differs from the file you receive, do not trust the draw.

**Derivation rule, in plain words:**
1. The seed is the drand round's randomness (the SHA-256 of the round's BLS
   signature), as a 64-character lowercase hex string.
2. Each manager gets a sort key: `SHA256("<seed>:<handle>")`, using the exact
   UTF-8 bytes of that string with no trailing newline.
3. Managers are sorted by sort key, ascending. Ties (astronomically unlikely)
   break by handle. That sorted order is the draft order — pick 1, pick 2, …

---

## 3. The seed source (committed in advance)

- Beacon: **drand "quicknet"** (the League of Entropy public randomness beacon)
- Chain hash: `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`
- **Round number: 29266612**
- **Signable at: 2026-06-04 20:00:00 UTC  (4:00 PM ET, Thursday, June 4, 2026)**
- After that instant, the round is fetchable by anyone, forever, at:
  `https://api.drand.sh/v2/beacons/quicknet/rounds/29266612`

Nobody — including the commissioner — can know round 29266612's value before it
is signed at the time above.

---

## 4. Review window

Managers: please confirm your handle appears in section 1 and that the
procedure looks correct **by 3:30 PM ET (19:30 UTC), Thursday, June 4, 2026**.
Once the round is signed at 4:00 PM ET, the result is final.

---

## 5. How the result will be produced and shared

Immediately after round 29266612 is signed at 4:00 PM ET, the commissioner runs:

```
python3 provably_fair_draw.py draw --round 29266612 --entrants managers.txt --out draw_result
```

and publishes `draw_result.txt` and `draw_result.json` — which contain the
seed, every manager's hash key, and the final pick order.

---

## 6. How to verify (no trust in the commissioner required)

Any one of these is sufficient on its own:

- **Re-run it:** `python3 provably_fair_draw.py verify --seed <SEED> --entrants managers.txt`
  — you should get a byte-identical order.
- **Check one row by hand** (any machine with coreutils):
  `printf '%s' "<SEED>:<your_handle>" | sha256sum`
  — the result must match your sort key in the published log. (Keep your
  handle inside the double quotes exactly as shown — that is what makes
  characters like `&` safe.)
- **Confirm the seed is real:** open
  `https://api.drand.sh/v2/beacons/quicknet/rounds/29266612`
  and check its randomness equals the SEED in the published log.
- **Confirm the code is the committed code:** the script's SHA-256 must equal
  the hash in section 2.

If all of these match, the draw was not manipulated.
