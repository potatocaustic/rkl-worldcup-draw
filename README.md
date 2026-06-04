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

## Verify it yourself 

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
