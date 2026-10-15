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

### Graphical (recommended)

```sh
python3 gui.py
```

- **Vault Policy** — create a new policy (demo or random keys), load or
  save a policy JSON, and edit every field: co-sign keys K1/K2/K3,
  cadence N, max fee F0, lattice size and fees, optional exit
  destination. Fields are validated live against the same rule layer
  the Coldcard runs.
- **Funding PSBT** — accept a funding PSBT two ways: **Choose PSBT
  file...** (picker) or paste the PSBT as **hex or base64** text.
  *Preview PSBT* parses it and shows input/output counts and funding
  value before you commit.
- **Build Vault Tree** — runs the full build and renders the report:
  funding mode, vault value, deposit txid, leaf files, and the
  **lattice root** with a one-click *Copy Lattice Root* button (compare
  it against the Coldcard screen at enrollment).
- Warnings (e.g. a funding output that will be replaced) and errors are
  surfaced in dialogs / the results pane.

tkinter is in the Python standard library; on Debian/Ubuntu:
`sudo apt install python3-tk`.

### Command line

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
python3 tests/test_vault_hostapp.py   # host app + CLI: 113 checks
python3 tests/test_gui_logic.py       # GUI logic layer: 29 checks
python3 tests/test_gui_smoke.py       # Tk app via mock tkinter: 15 checks
python3 tests/test_gui_real.py        # REAL GUI (needs display): 17 checks
```

`test_gui_real.py` SKIPs cleanly on headless machines. The full stack is
also integration-tested against the real Coldcard simulator: a tree
built through the GUI's code path runs enroll → lattice → signing gate →
wipe inside `coldcard-mpy` (real firmware parser and policy) via
`VAULT_E2E_DIR=<tree> unix/vault_sim_e2e.py` — which is how the leaf
input-map bug below was caught.

### Bug found by the device integration test

Leaf PSBTs originally carried only the witness utxo. The Coldcard
requires, on every vault input: the witness utxo (`0x01`), the witness
script S_v (`0x05` — needed for script recognition and partial-signature
verification), and the full non-witness UTXO (`0x00`, the deposit tx —
needed for the P1 fee-window txid cross-check). Without these the
device refuses to enroll the lattice. Fixed in `vault_tree.py`; lattice
roots are unaffected (leaf hashes cover the unsigned tx, not the PSBT
maps).

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
