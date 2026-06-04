#!/usr/bin/env bash
# bootstrap.sh — recreate the provably-fair "World Cup" draw repo in a Linux
# shell (a GitHub Codespace or any cloud shell), byte-for-byte, then verify the
# draw tool's hash before committing.  Usage:  bash bootstrap.sh [git-remote-url]
set -euo pipefail

EXPECTED_HASH="078f74ea805f1d1029062725a9fe4229f597e91cc2fe4ae539a32c51e762552f"

echo ">> Writing files (LF line endings, exact bytes)..."
mkdir -p .github/workflows
cat > 'provably_fair_draw.py' <<'EOF_provably_fair_draw_py_Z'
#!/usr/bin/env python3
"""
provably_fair_draw.py
=====================

Verifiable, tamper-evident random draw for an N-entrant draft (built for a
48-team "World Cup" fantasy league, but the entrant list is arbitrary -- swap
in manager handles, the 48 national teams, whatever the 48 things are).

WHY THIS IS PROVABLE
--------------------
A draw is only "provably unmanipulated" if three things are true, in order:

  1. COMMITMENT: the exact entrant list, the exact algorithm, and the exact
     FUTURE seed source are fixed and published *before* the seed exists.
  2. UNPREDICTABLE PUBLIC SEED: randomness from a public source you cannot
     control or predict, permanently recorded so anyone can look it up. We use
     the drand "quicknet" beacon (League of Entropy). A Bitcoin block hash
     works too.
  3. DETERMINISTIC, REPRODUCIBLE MAPPING: seed -> order is a published,
     implementation-independent function. Each entrant's sort key is
     SHA256("seed:name"); sort ascending. Anyone can recompute one row with
     `printf '%s' "SEED:NAME" | sha256sum` -- no tooling, no trust in this code.

The classic mistake is `random.seed(<a number you chose>)`. That proves
nothing even if you publish it: you could have ground thousands of seeds
offline until one gave an order you liked. The seed MUST come from outside,
AFTER you have committed.

ENCODING NOTE (read this -- it is the #1 cause of "verification doesn't match")
The preimage is the exact UTF-8 bytes of  f"{seed}:{name}"  with NO trailing
newline. Entrant names here are deliberately ASCII and shell-safe (no
diacritics, no '&', no ':') so manual `sha256sum` checks are unambiguous.
If you localize names (Turkiye, Curacao, Cote d'Ivoire...), pin UTF-8 NFC and
expect to explain it.

PAPER TRAIL (run order)
-----------------------
  python provably_fair_draw.py self-hash               # pin script SHA256
  python provably_fair_draw.py sample-entrants         # writes entrants.txt
  # --- PUBLISH COMMITMENT NOW: list + script hash + target round + this file
  python provably_fair_draw.py round-for-time 2026-06-10T18:00:00Z
  # ... wait until after that instant ...
  python provably_fair_draw.py draw --round <N> --entrants entrants.txt --out draw_result
  # --- PUBLISH draw_result.json / draw_result.txt ---
  # Anyone re-runs the same command and gets byte-identical output.

Verification by a participant who does not trust this script:
  python provably_fair_draw.py verify --seed <SEED> --entrants entrants.txt
  # or per-row:  printf '%s' "<SEED>:France" | sha256sum
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import urllib.request
from typing import List, Tuple

# --- drand quicknet (League of Entropy mainnet) ----------------------------
# Verified against docs.drand.love (June 2026). quicknet = unchained,
# BLS12-381 G1, RFC9380; a new beacon every 3 s. The random value for a round
# is DEFINED as sha256(signature_bytes).
QUICKNET_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_GENESIS = 1692803367  # unix seconds; round 1 signable at genesis
QUICKNET_PERIOD = 3            # seconds per round

# Independent public relays. We require >=2 reachable relays to AGREE and we
# fail loudly on any disagreement -- we never silently trust a single relay.
# (Multi-relay agreement is a lightweight integrity check. The cryptographic
# gold standard is BLS verification against the quicknet group public key via
# the official drand client libraries -- see README note at bottom.)
DRAND_RELAYS = [
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
]

DELIMITER = ":"  # entrant names must not contain this byte

SAMPLE_48 = [
    "Algeria", "Argentina", "Australia", "Austria", "Belgium",
    "Bosnia and Herzegovina", "Brazil", "Canada", "Cape Verde", "Colombia",
    "Croatia", "Curacao", "Czechia", "DR Congo", "Ecuador", "Egypt",
    "England", "France", "Germany", "Ghana", "Haiti", "Iran", "Iraq",
    "Ivory Coast", "Japan", "Jordan", "Mexico", "Morocco", "Netherlands",
    "New Zealand", "Norway", "Panama", "Paraguay", "Portugal", "Qatar",
    "Saudi Arabia", "Scotland", "Senegal", "South Africa", "South Korea",
    "Spain", "Sweden", "Switzerland", "Tunisia", "Turkiye", "United States",
    "Uruguay", "Uzbekistan",
]

# --- round <-> time --------------------------------------------------------

def round_at(when: dt.datetime) -> int:
    """First drand round signable at or after `when` (UTC-aware)."""
    ts = int(when.timestamp())
    if ts < QUICKNET_GENESIS:
        raise ValueError("target time precedes drand quicknet genesis")
    n = (ts - QUICKNET_GENESIS) // QUICKNET_PERIOD + 1
    while QUICKNET_GENESIS + (n - 1) * QUICKNET_PERIOD < ts:
        n += 1
    return n


def time_of_round(n: int) -> dt.datetime:
    secs = QUICKNET_GENESIS + (n - 1) * QUICKNET_PERIOD
    return dt.datetime.fromtimestamp(secs, tz=dt.timezone.utc)

# --- seed fetch + cross-check ----------------------------------------------

def _fetch_round_from(relay: str, rnd: int, timeout: float = 10.0) -> dict:
    url = f"{relay}/v2/beacons/quicknet/rounds/{rnd}"
    req = urllib.request.Request(url, headers={"User-Agent": "provably-fair-draw/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    if data.get("round") != rnd:
        raise ValueError(f"{relay}: returned round {data.get('round')} != {rnd}")
    sig = data["signature"].lower()
    # randomness is defined as sha256(signature) for unchained quicknet.
    computed = hashlib.sha256(bytes.fromhex(sig)).hexdigest()
    reported = (data.get("randomness") or computed).lower()
    if reported != computed:
        raise ValueError(f"{relay}: reported randomness != sha256(signature)")
    return {"relay": relay, "signature": sig, "randomness": computed}


def fetch_seed(rnd: int) -> dict:
    """Fetch round `rnd` from every relay; require unanimous agreement.

    Raises (no silent degradation) if fewer than two relays are reachable or if
    any reachable relay disagrees -- a single source is not good enough for a
    draw you intend to defend. Records which relays agreed and which failed.
    """
    results: List[dict] = []
    errors: List[Tuple[str, str]] = []
    for relay in DRAND_RELAYS:
        try:
            results.append(_fetch_round_from(relay, rnd))
        except Exception as e:  # noqa: BLE001 -- surface every relay failure
            errors.append((relay, repr(e)))

    if len(results) < 2:
        raise RuntimeError(
            f"need >=2 reachable relays for a defensible draw, got "
            f"{len(results)}. failures={errors}"
        )
    signatures = {r["signature"] for r in results}
    if len(signatures) != 1:
        raise RuntimeError(
            f"RELAY DISAGREEMENT on round {rnd} -- refusing to proceed: {results}"
        )

    return {
        "source": "drand-quicknet",
        "chain_hash": QUICKNET_CHAIN_HASH,
        "round": rnd,
        "round_time_utc": time_of_round(rnd).isoformat(),
        "signature": results[0]["signature"],
        "seed": results[0]["randomness"],
        "relays_agreed": [r["relay"] for r in results],
        "relays_failed": errors,
    }

# --- the draw (deterministic, implementation-independent) ------------------

def entrant_key(seed: str, name: str) -> str:
    if DELIMITER in name:
        raise ValueError(f"entrant {name!r} contains reserved delimiter {DELIMITER!r}")
    preimage = f"{seed}{DELIMITER}{name}".encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


def draw(seed: str, entrants: List[str]) -> List[Tuple[int, str, str]]:
    if len(set(entrants)) != len(entrants):
        raise ValueError("duplicate entrant names -- list must be unique")
    keyed = [(entrant_key(seed, n), n) for n in entrants]
    keyed.sort(key=lambda kn: (kn[0], kn[1]))  # key asc, name as total tiebreak
    return [(i + 1, name, key) for i, (key, name) in enumerate(keyed)]

# --- audit artifact --------------------------------------------------------

def self_sha256() -> str:
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def render_audit_text(seed_info: dict, order: List[Tuple[int, str, str]]) -> str:
    lines = [
        "PROVABLY-FAIR DRAW -- AUDIT LOG",
        "=" * 70,
        f"protocol      : commit -> public drand seed -> sha256 sort key",
        f"script SHA256 : {self_sha256()}",
        f"seed source   : {seed_info['source']}  (chain {seed_info['chain_hash'][:16]}...)",
        f"drand round   : {seed_info['round']}",
        f"round time    : {seed_info['round_time_utc']}",
        f"signature     : {seed_info['signature']}",
        f"SEED          : {seed_info['seed']}",
        f"relays agreed : {', '.join(seed_info['relays_agreed'])}",
        "-" * 70,
        f"{'PICK':<5}{'ENTRANT':<30}SORT KEY = sha256('seed:entrant')",
    ]
    for pick, name, key in order:
        lines.append(f"{pick:<5}{name:<30}{key}")
    lines.append("-" * 70)
    lines.append(
        "VERIFY ANY ROW:  printf '%s' \""
        + seed_info["seed"] + DELIMITER + "<ENTRANT>\" | sha256sum"
    )
    return "\n".join(lines) + "\n"


def write_audit(seed_info: dict, entrants: List[str],
                order: List[Tuple[int, str, str]], out: str) -> None:
    payload = {
        "protocol": "commit -> public drand seed -> sha256 sort key",
        "script_sha256": self_sha256(),
        "seed_info": seed_info,
        "delimiter": DELIMITER,
        "entrant_count": len(entrants),
        "entrants_committed_list": entrants,
        "result": [{"pick": p, "entrant": n, "sort_key": k} for p, n, k in order],
    }
    with open(f"{out}.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    text = render_audit_text(seed_info, order)
    with open(f"{out}.txt", "w", encoding="utf-8") as f:
        f.write(text)
    sys.stdout.write(text)

# --- CLI -------------------------------------------------------------------

def _read_entrants(path: str) -> List[str]:
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(
        description="Provably-fair random draw via the drand public beacon."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("self-hash", help="print this script's SHA256 (for the commitment)")
    sub.add_parser("sample-entrants", help="write entrants.txt with the 48 WC nations")

    p_r = sub.add_parser("round-for-time", help="drand round at/after a UTC instant")
    p_r.add_argument("when", help="ISO-8601, e.g. 2026-06-10T18:00:00Z")

    p_d = sub.add_parser("draw", help="fetch seed + produce the draw + write audit log")
    p_d.add_argument("--round", type=int, required=True)
    p_d.add_argument("--entrants", required=True, help="text file, one name per line")
    p_d.add_argument("--out", default="draw_result")

    p_v = sub.add_parser("verify", help="re-derive order from a known seed (offline)")
    p_v.add_argument("--seed", required=True)
    p_v.add_argument("--entrants", required=True)

    a = ap.parse_args(argv)

    if a.cmd == "self-hash":
        print(self_sha256())
    elif a.cmd == "sample-entrants":
        with open("entrants.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(SAMPLE_48) + "\n")
        print(f"wrote entrants.txt with {len(SAMPLE_48)} entrants")
    elif a.cmd == "round-for-time":
        when = dt.datetime.fromisoformat(a.when.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        n = round_at(when.astimezone(dt.timezone.utc))
        print(f"round {n}  (signable at {time_of_round(n).isoformat()})")
    elif a.cmd == "draw":
        entrants = _read_entrants(a.entrants)
        seed_info = fetch_seed(a.round)
        order = draw(seed_info["seed"], entrants)
        write_audit(seed_info, entrants, order, a.out)
    elif a.cmd == "verify":
        entrants = _read_entrants(a.entrants)
        for pick, name, key in draw(a.seed, entrants):
            print(f"{pick:>3}. {name:<30} {key}")


if __name__ == "__main__":
    main()
EOF_provably_fair_draw_py_Z
cat > 'managers.txt' <<'EOF_managers_txt_Z'
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
EOF_managers_txt_Z
cat > 'COMMITMENT.md' <<'EOF_COMMITMENT_md_Z'
# RKL "World Cup" Manager Draft — Draw Commitment

**Posted:** << fill in the actual time you publish this — it MUST be before the 3:30 PM ET review deadline in section 4 >>

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

- Tool: `provably_fair_draw.py` (attached / linked: << repo or gist URL >>)
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
<< Optional: this runs automatically via a GitHub Action triggered after
4:00 PM ET, so the result is committed without the commissioner touching it.
Link: ___ >>

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
EOF_COMMITMENT_md_Z
cat > 'README.md' <<'EOF_README_md_Z'
# RKL "World Cup" Manager Draft — Provably-Fair Draw

A tamper-evident random draw for 48 league managers. The pick order is derived
from a public, unpredictable randomness beacon (drand) that nobody — including
the commissioner — can control, using a procedure that was published **before**
the random value existed. Anyone can reproduce the result and confirm it was not
manipulated.

## Files

| File | Purpose |
|------|---------|
| `COMMITMENT.md` | The frozen procedure — the 48 managers, the algorithm + its SHA-256, the exact drand round, and how to verify. Published before the seed existed. **Do not edit.** |
| `provably_fair_draw.py` | The draw tool. **Do not edit** — its SHA-256 is recorded in `COMMITMENT.md`; any change invalidates the proof. |
| `managers.txt` | The 48 manager handles (the draw input). **Do not edit.** |
| `.github/workflows/draw.yml` | Optional automation: runs the draw after the round time and commits the result. Safe to edit (it is not part of the hashed commitment). |
| `draw_result.txt` / `draw_result.json` | The result — seed, every handle's hash key, and the final pick order. Published after the round. |

## The draw

- **Seed:** drand quicknet **round 29266612**, signed at **2026-06-04 20:00 UTC (4:00 PM ET)**.
- **Produced by:**
  ```
  python3 provably_fair_draw.py draw --round 29266612 --entrants managers.txt --out draw_result
  ```

## Verify it yourself (no trust in the commissioner required)

Full details in `COMMITMENT.md` §6. In short:

1. Confirm the tool is the committed code: `python3 provably_fair_draw.py self-hash`
   must equal the SHA-256 in `COMMITMENT.md` §2.
2. Confirm the seed is real: open
   `https://api.drand.sh/v2/beacons/quicknet/rounds/29266612` and check its
   randomness equals the SEED in the published result.
3. Reproduce the order:
   `python3 provably_fair_draw.py verify --seed <SEED> --entrants managers.txt`
   — byte-identical to the published order.
4. Or spot-check one row with nothing but coreutils:
   `printf '%s' "<SEED>:<your_handle>" | sha256sum`.

If all match, the draw was not manipulated.
EOF_README_md_Z
cat > '.gitattributes' <<'EOF__gitattributes_Z'
# Disable git's end-of-line conversion for the frozen files so their SHA-256 is
# identical on Windows, macOS, and Linux. The draw verification depends on this:
# a cloner on a different OS must compute the same hash the commitment records.
provably_fair_draw.py -text
managers.txt -text
COMMITMENT.md -text
EOF__gitattributes_Z
cat > '.gitignore' <<'EOF__gitignore_Z'
__pycache__/
*.pyc
.DS_Store
.venv/
venv/
# local scratch (not part of the repo)
managers_raw.txt
dryrun.*
EOF__gitignore_Z
cat > '.github/workflows/draw.yml' <<'EOF__github_workflows_draw_yml_Z'
name: World Cup Draw

# For a same-day, one-shot draw, trigger this MANUALLY at 4:00 PM ET using the
# "Run workflow" button on the Actions tab (workflow_dispatch). The cron below
# is only a backstop: GitHub's scheduled runs can lag 5-20+ minutes, which is
# harmless here because round 29266612 is fixed (a late run produces the
# identical result) -- but do not rely on cron alone for timing.
on:
  workflow_dispatch:
  schedule:
    - cron: "10 20 4 6 *"   # 20:10 UTC on June 4 (backstop only)

permissions:
  contents: write           # required so the job can commit the result back

jobs:
  draw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      # provably_fair_draw.py uses only the Python standard library -- no deps.
      - name: Produce the draw from the committed round
        run: python3 provably_fair_draw.py draw --round 29266612 --entrants managers.txt --out draw_result
      - name: Publish the result
        run: |
          git config user.name "draw-bot"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add draw_result.json draw_result.txt
          git diff --staged --quiet || git commit -m "Draw result — drand quicknet round 29266612"
          git push
EOF__github_workflows_draw_yml_Z

echo ">> Verifying draw-tool integrity..."
GOT="$(python3 provably_fair_draw.py self-hash)"
if [ "$GOT" != "$EXPECTED_HASH" ]; then
  echo "!! HASH MISMATCH: got $GOT" >&2
  echo "!! expected      $EXPECTED_HASH" >&2
  echo "!! Refusing to continue. In a Linux shell this should match exactly." >&2
  exit 1
fi
echo "   OK -- script hash matches the value committed in COMMITMENT.md."

echo ">> Initializing git and committing..."
[ -d .git ] || git init -q
git add -A
git -c user.name="draw-setup" -c user.email="draw-setup@local" commit -q -m "Commit draw procedure" || echo "   (nothing new to commit)"

echo ">> SHA-256 of COMMITMENT.md  (post THIS in the league chat before 3:30 PM ET):"
sha256sum COMMITMENT.md

REMOTE="${1:-}"
if [ -n "$REMOTE" ]; then
  echo ">> Pushing to: $REMOTE"
  git branch -M main
  git remote remove origin 2>/dev/null || true
  git remote add origin "$REMOTE"
  git push -u origin main
elif git remote get-url origin >/dev/null 2>&1; then
  echo ">> Existing 'origin' remote detected -- pushing..."
  git branch -M main
  git push -u origin main
else
  echo ">> No remote set. Create an empty PUBLIC GitHub repo, then run:"
  echo "     git branch -M main && git remote add origin <repo-url> && git push -u origin main"
  echo "   (or, if gh is authenticated:  gh repo create rkl-worldcup-draw --public --source=. --push )"
fi

echo
echo ">> DONE.  Do NOT run the draw until 4:00 PM ET."
echo "   At 4:00 PM ET, produce + publish the result:"
echo "     python3 provably_fair_draw.py draw --round 29266612 --entrants managers.txt --out draw_result"
echo "     git add draw_result.* && git commit -m 'Draw result' && git push"
