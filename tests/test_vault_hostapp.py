# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# testing/test_vault_hostapp.py - host tests for hostapp/vault_tree.py.
#
# Exercises the funding shapes (input-only, incorrect output,
# already-correct, already-correct w/ the vault output NOT at vout 0),
# verifies the built tree (deposit pays S_v, output-map counts, leaf
# fees, leaves spend the correct deposit vout, witness utxos chained to
# the deposit txid) and re-derives the lattice root INDEPENDENTLY from
# the written PSBT files. Also: N push-encoding across the valid cadence
# range, unknown 0x01-prefixed input-map keys, zero-padded leaf names,
# and refusal of ambiguous/insane funding.
#
# Run: python3 testing/test_vault_hostapp.py

import os, sys, json, shutil, subprocess, tempfile, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
# vault_tree.py + vault_policy.py live at the repo root of this
# standalone host app (in the firmware tree they lived in hostapp/ and
# shared/ respectively)
sys.path.insert(0, os.path.join(HERE, '..'))
import vault_tree as vt
import vault_policy as vp

APP = os.path.join(HERE, '..', 'vault_tree.py')
FUNDING_VALUE = 100000
DEPOSIT_FEE = 500

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    print('%s: %s' % ('ok' if cond else 'FAIL', name))

def make_policy(tmp, leaves=5, name='policy.json'):
    # fixed demo keys (same as init-policy defaults)
    pol = {
        'k1': (b'\x02' + bytes(range(1, 33))).hex(),
        'k2': (b'\x03' + bytes(range(33, 65))).hex(),
        'k3': (b'\x02' + bytes(range(65, 97))).hex(),
        'n': 1008, 'f0_max': 10000, 'leaves': leaves,
        'emg_fee': 500, 'emg_step': 13, 'deposit_fee': DEPOSIT_FEE,
    }
    path = os.path.join(tmp, name)
    open(path, 'w').write(json.dumps(pol))
    return path

def make_funding(tmp, kind, spk_v, name):
    # one-input funding PSBT in the requested shape
    ins = [(hashlib.sha256(b'fund:' + name.encode()).digest(), 0, 0xFFFFFFFE)]
    if kind == 'input-only':
        outs = []
    elif kind == 'incorrect':
        outs = [(vp.p2wsh_spk(b'\x51' + b'\x00' * 40),
                 FUNDING_VALUE - DEPOSIT_FEE)]
    elif kind == 'correct':
        outs = [(spk_v, FUNDING_VALUE - DEPOSIT_FEE)]
    elif kind == 'correct-vout1':
        # already-correct, but the vault output is at vout 1 (change first)
        outs = [(vp.p2wsh_spk(b'\x42' + b'\x00' * 40), 100),
                (spk_v, FUNDING_VALUE - DEPOSIT_FEE)]
    elif kind == 'multi-vault':
        # ambiguous: two outputs pay S_v -> must be refused
        outs = [(spk_v, 100), (spk_v, FUNDING_VALUE - DEPOSIT_FEE - 100)]
    elif kind == 'overpay':
        # outputs sum > inputs -> must be refused
        outs = [(vp.p2wsh_spk(b'\x43' + b'\x00' * 40), 90000),
                (spk_v, FUNDING_VALUE - DEPOSIT_FEE)]
    else:
        raise ValueError(kind)
    tx = vt.ser_tx(2, ins, outs, 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
    path = os.path.join(tmp, name + '.psbt')
    open(path, 'wb').write(vt.build_psbt(tx, [im], len(outs)))
    return path

def run_app(policy, funding, outdir):
    r = subprocess.run(
        [sys.executable, APP, 'build', policy, funding, outdir],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr)
    return r

def check_tree(outdir, mode, vout=0):
    man = json.loads(open(os.path.join(outdir, 'manifest.json')).read())
    ok('mode == %s' % mode, man['funding_mode'] == mode)
    ok('vault value', man['vault_value'] == FUNDING_VALUE - DEPOSIT_FEE)
    ok('vault vout == %d' % vout, man['vault_vout'] == vout)

    s_v, s_e = vt.build_scripts({
        'k1': bytes.fromhex(man['cfg']['k1_pubkey']),
        'k2': b'\x03' + bytes(range(33, 65)),
        'k3': b'\x02' + bytes(range(65, 97)),
        'n': man['cfg']['n']})
    spk_v, spk_e = vp.p2wsh_spk(s_v), vp.p2wsh_spk(s_e)
    ok('cfg sv_hash/spk_e match scripts',
       man['cfg']['sv_hash'] == spk_v.hex() and
       man['cfg']['spk_e'] == spk_e.hex())

    # deposit: outputs paying S_v at vout `vout` w/ the vault value
    # (also a map-count regression: parse_psbt now consumes one map per
    # output and rejects map/output count mismatches)
    dep = vt.parse_psbt(open(os.path.join(outdir, 'deposit.psbt'), 'rb').read())
    _, _, outs, _ = vt.parse_tx(dep['tx'])
    ok('deposit pays S_v at vout %d' % vout,
       len(outs) == vout + 1 and
       outs[vout] == (spk_v, FUNDING_VALUE - DEPOSIT_FEE))
    ok('deposit non-vault outputs kept',
       vout == 0 or all(outs[i][0] != spk_v for i in range(vout)))
    ok('deposit keeps funding input maps', len(dep['in_maps']) == 1
       and dep['in_maps'][0][-1:] == b'\x00')

    # map-count enforcement: fewer output maps than outputs must fail
    bad = vt.build_psbt(dep['tx'], dep['in_maps'], 1)
    try:
        vt.parse_psbt(bad)
        ok('output-map count enforced', vout == 0)
    except Exception:
        ok('output-map count enforced', vout == 1)

    # leaves: spend the deposit txid at vout `vout` (NOT always 0:
    # regression - an already-correct funding w/ the vault output at
    # vout 1 made the leaves spend the change output), S_v witness
    # utxo, fee ladder
    dep_txid = vt.txid_of(dep['tx'])
    fees = []
    for i, f in enumerate(man['files']):
        p = vt.parse_psbt(open(os.path.join(outdir, f), 'rb').read())
        _, ins, outs, lt = vt.parse_tx(p['tx'])
        ok('%s shape' % f,
           len(ins) == 1 and ins[0][0] == dep_txid and ins[0][1] == vout
           and ins[0][2] == vp.SEQ_EMERGENCY and lt == 0
           and len(outs) == 1 and outs[0][0] == spk_e)
        ok('%s witness utxo' % f,
           len(p['wutxos']) == 1 and p['wutxos'][0] == (
               spk_v, FUNDING_VALUE - DEPOSIT_FEE))
        fees.append((FUNDING_VALUE - DEPOSIT_FEE) - outs[0][1])
    ok('fee ladder 500..552', fees == [500 + 13 * i for i in range(5)])

    # independent root: re-derive from the FILES, not the manifest
    leaves = [vp.leaf_hash(i, vt.parse_psbt(open(
        os.path.join(outdir, f), 'rb').read())['tx'])
        for i, f in enumerate(man['files'])]
    root, count = vp.lattice_root(iter(leaves))
    ok('root matches independent re-derive',
       root.hex() == man['lattice_root'] and count == man['lattice_count'])
    return man

def test_n_encoding():
    # build_scripts must emit a parse_vault_script-acceptable N push for
    # the whole valid cadence range (regression: the old non-minimal,
    # unpadded push crashed the structural self-check with
    # 'negative pushnum' for 128 <= N <= 255 and 0x8000 <= N <= 0xffff)
    def keys(n):
        return {'k1': b'\x02' + bytes(range(1, 33)),
                'k2': b'\x03' + bytes(range(33, 65)),
                'k3': b'\x02' + bytes(range(65, 97)), 'n': n}
    for n in (1, 16, 17, 100, 127, 128, 200, 255, 256, 1008,
              0x7fff, 0x8000, 0x8001, 0xffff):
        s_v, s_e = vt.build_scripts(keys(n))
        ok('build_scripts N=0x%x' % n,
           vp.parse_vault_script(s_v)['n'] == n)
    for bad in (0, 0x10000):
        try:
            vt.build_scripts(keys(bad))
            ok('build_scripts N=0x%x refused' % bad, False)
        except SystemExit:
            ok('build_scripts N=0x%x refused' % bad, True)

def test_unknown_key(tmp, policy, spk_v):
    # BIP-174: the PSBT_IN_WITNESS_UTXO key is exactly b'\x01'; keys of
    # the form '01 <data>' are unknown keys, passed through verbatim,
    # and must NOT be read as utxos (regression: an unknown 0x01-
    # prefixed key inflated total_in and so the vault value)
    ins = [(hashlib.sha256(b'fund:unknownkey').digest(), 0, 0xFFFFFFFE)]
    tx = vt.ser_tx(2, ins, [], 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    bogus = vt.ct_out(b'\x21' * 34, 1000000)   # value shaped like a CTxOut
    im = (vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu +        # the real one
          vt.vi(3) + b'\x01\x66\x00' + vt.vi(len(bogus)) + bogus +  # unknown
          b'\x00')
    path = os.path.join(tmp, 'fund-unknownkey.psbt')
    open(path, 'wb').write(vt.build_psbt(tx, [im], 0))
    ps = vt.parse_psbt(open(path, 'rb').read())
    ok('unknown 01-prefixed key ignored', len(ps['wutxos']) == 1)
    ok('unknown key passed through verbatim',
       len(ps['in_maps']) == 1 and b'\x01\x66\x00' in ps['in_maps'][0])
    r = run_app(policy, path, os.path.join(tmp, 'tree-unknownkey'))
    ok('app run (unknown key)', r.returncode == 0)
    if r.returncode == 0:
        man = json.loads(open(os.path.join(tmp, 'tree-unknownkey',
                                           'manifest.json')).read())
        ok('vault value not inflated',
           man['funding_mode'] == 'input-only' and
           man['vault_value'] == FUNDING_VALUE - DEPOSIT_FEE)

def test_zero_pad(tmp, spk_v):
    # leaf filenames are zero-padded to a fixed width so that the device
    # file picker's lexicographic sort order == the numeric leaf order
    # (regression: 'emg10' sorts before 'emg2', scrambling the
    # pick-order leaf index for >= 10 leaves)
    policy = make_policy(tmp, leaves=11, name='policy-11.json')
    fund = make_funding(tmp, 'input-only', spk_v, 'fund-pad')
    r = run_app(policy, fund, os.path.join(tmp, 'tree-pad'))
    ok('app run (11 leaves)', r.returncode == 0)
    if r.returncode == 0:
        man = json.loads(open(os.path.join(tmp, 'tree-pad',
                                           'manifest.json')).read())
        ok('leaf names fixed width (emg00..emg10)',
           man['files'] == ['emg%02d.psbt' % i for i in range(11)])
        ok('filename sort == leaf order',
           sorted(man['files']) == man['files'])

def test_exit_spk_shape(tmp, spk_v):
    # exit destinations are confined to P2WSH (device-side VaultPolicy
    # check): a non-P2WSH exit_spk override must be refused by the app
    # (better message than the device's enrollment refusal), and a
    # valid P2WSH override must pass through to the manifest cfg
    fund = make_funding(tmp, 'input-only', spk_v, 'fund-exit')

    bad = make_policy(tmp, name='policy-badexit.json')
    d = json.loads(open(bad).read())
    d['exit_spk'] = '0014' + '11' * 20          # P2WPKH: not P2WSH
    open(bad, 'w').write(json.dumps(d))
    r = run_app(bad, fund, os.path.join(tmp, 'tree-badexit'))
    ok('non-P2WSH exit_spk refused',
       r.returncode != 0 and 'P2WSH' in (r.stdout + r.stderr))

    good = make_policy(tmp, name='policy-goodexit.json')
    d = json.loads(open(good).read())
    d['exit_spk'] = vp.p2wsh_spk(b'\x71' * 32).hex()   # valid P2WSH
    open(good, 'w').write(json.dumps(d))
    r = run_app(good, fund, os.path.join(tmp, 'tree-goodexit'))
    ok('P2WSH exit_spk override accepted', r.returncode == 0)
    if r.returncode == 0:
        man = json.loads(open(os.path.join(tmp, 'tree-goodexit',
                                           'manifest.json')).read())
        ok('override carried to manifest cfg',
           man['cfg']['exit_spk'] == vp.p2wsh_spk(b'\x71' * 32).hex())


def main():
    tmp = tempfile.mkdtemp(prefix='vault-hostapp-')
    try:
        policy = make_policy(tmp)
        s_v, _ = vt.build_scripts({
            'k1': b'\x02' + bytes(range(1, 33)),
            'k2': b'\x03' + bytes(range(33, 65)),
            'k3': b'\x02' + bytes(range(65, 97)), 'n': 1008})
        spk_v = vp.p2wsh_spk(s_v)

        test_n_encoding()

        for kind, mode, vout in (('input-only', 'input-only', 0),
                                 ('incorrect', 'incorrect-output', 0),
                                 ('correct', 'already-correct', 0),
                                 ('correct-vout1', 'already-correct', 1)):
            fund = make_funding(tmp, kind, spk_v, 'fund-' + kind)
            outdir = os.path.join(tmp, 'tree-' + kind)
            r = run_app(policy, fund, outdir)
            ok('app run (%s)' % kind, r.returncode == 0)
            if r.returncode != 0:
                continue
            man = check_tree(outdir, mode, vout)
            if kind == 'input-only':
                # keep for the device-driver run (see docs/vault_progress.md)
                shutil.copytree(outdir, os.path.join(HERE, '..', 'unix',
                                                     'work', 'app-tree'),
                                dirs_exist_ok=True)
                print('  (app tree copied to unix/work/app-tree for the '
                      'device run)')
            if kind == 'correct-vout1':
                # regression check (again, explicitly): leaves must NOT
                # spend vout 0 when the vault output is at vout 1
                p = vt.parse_psbt(open(os.path.join(
                    outdir, man['files'][0]), 'rb').read())
                _, ins, _, _ = vt.parse_tx(p['tx'])
                ok('leaves spend the vault vout (not 0)', ins[0][1] == 1)

        # ambiguous / insane funding refused
        for kind, why in (('multi-vault', 'outputs pay S_v'),
                          ('overpay', 'exceed inputs')):
            fund = make_funding(tmp, kind, spk_v, 'fund-' + kind)
            r = run_app(policy, fund, os.path.join(tmp, 'tree-' + kind))
            ok('%s funding refused (%s)' % (kind, why),
               r.returncode != 0 and why in (r.stdout + r.stderr))

        test_unknown_key(tmp, policy, spk_v)
        test_zero_pad(tmp, spk_v)
        test_exit_spk_shape(tmp, spk_v)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(1 for _, c in R if c)
    print('VAULT HOSTAPP: %d/%d checks pass' % (n, len(R)))
    if n != len(R):
        sys.exit(1)

if __name__ == '__main__':
    main()
