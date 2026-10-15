# Coldcard Vault Host App

Standalone host side of the vault co-signing protocol for the
[Coldcard](https://coldcard.com) vault firmware (a fork of
[Coldcard/firmware](https://github.com/Coldcard/firmware); see the
firmware-side work in [Shitnobi/coldcard-firmware](https://github.com/Shitnobi/coldcard-firmware)).

This repo contains everything needed to **plan, fund, and verify** a
vault deposit on an ordinary computer — no device firmware required:

- **`vault_tree.py`** — the host application. Accepts a funding PSBT and
  constructs the full vault transaction tree:
  - `deposit.psbt` — funding → S_v (P2WSH of the branched vault script)
  - `emg<i>.psbt` — pre-authorized emergency exits S_v → S_e (the
    lattice leaves; what gets enrolled on the Coldcard)
  - `manifest.json` — device-enrollment cfg + host lattice root (compare
    against the root the device displays at enrollment)
- **`vault_policy.py`** — the pure policy/rule core (script shapes,
  leaf hashing, Merkle root, spend-class checks). Identical to the
  module the device firmware runs, so host and device agree by
  construction.

## Usage

```sh
# 1. create a policy file (edit it: keys, cadence n, fee window)
python3 vault_tree.py init-policy policy.json

# 2. build the vault tree from your funding PSBT
python3 vault_tree.py build policy.json funding.psbt outdir/ \
    [--deposit-fee 500] [--leaves 5] [--emg-fee 500] [--emg-step 13]

# 3. enroll 'outdir/manifest.json' + the emg<i>.psbt leaves on the
#    Coldcard (Enroll Policy -> Enroll Lattice), and confirm the
#    device-displayed lattice root equals the manifest's
```

The CSV cadence (vault delay) is the `"n"` field in the policy file —
a single knob, in blocks (1–65535). Note it applies to new vaults
only; already-funded coins have N committed in their on-chain script.

## Tests

```sh
python3 tests/test_vault_hostapp.py
```

Exercises the funding shapes (input-only, incorrect output,
already-correct, vault output not at vout 0), verifies the built tree
(deposit pays S_v, leaf fees, leaves spend the correct deposit vout,
witness utxos chained to the deposit txid), re-derives the lattice
root independently from the written PSBT files, and checks N
push-encoding across the valid cadence range and refusal of
ambiguous/insane funding.

## Provenance & sync

Extracted from the firmware repo (`hostapp/vault_tree.py` +
`shared/vault_policy.py` + `testing/test_vault_hostapp.py`), commit
`0d2709cc`. The two copies must stay in sync: `vault_policy.py` is
byte-identical to the firmware's `shared/vault_policy.py` by design —
any policy change must be made in both repos (or re-extracted) so the
host and device rule layers cannot diverge.

## License

(c) Copyright 2026 for the vault co-sign policy work; license per
COPYING-CC (permissive, Coinkite-style).
