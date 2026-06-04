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
