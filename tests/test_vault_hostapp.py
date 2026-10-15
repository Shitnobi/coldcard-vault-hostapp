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
    except (Exception, vt.HostappError):
        # HostappError is SystemExit (BaseException), not Exception
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


def test_dup_key(tmp, policy, spk_v):
    # HA-3 (audit #2): BIP-174 forbids duplicate keys within a map. A
    # duplicated 0x01 witness-utxo key used to be read twice, inflating
    # total_in and the built vault value (deposit paying out 2x the
    # inputs). Must be refused.
    ins = [(hashlib.sha256(b'fund:dupkey').digest(), 0, 0xFFFFFFFE)]
    tx = vt.ser_tx(2, ins, [], 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = (vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu +
          vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu +   # DUPLICATE key
          b'\x00')
    path = os.path.join(tmp, 'fund-dupkey.psbt')
    open(path, 'wb').write(vt.build_psbt(tx, [im], 0))
    try:
        vt.parse_psbt(open(path, 'rb').read())
        ok('duplicate map key refused (parser)', False)
    except vt.HostappError as e:
        ok('duplicate map key refused (parser)',
           'duplicate key' in str(e) and 'BIP-174' in str(e))
    r = run_app(policy, path, os.path.join(tmp, 'tree-dupkey'))
    ok('duplicate map key refused (app)',
       r.returncode != 0 and 'duplicate key' in (r.stdout + r.stderr) and
       'Traceback' not in (r.stdout + r.stderr))


def test_truncated(tmp, policy, spk_v):
    # HA-2/HA-13 (audit #2): a truncated/malformed PSBT must be refused
    # with a clean error (no traceback, no silent GUI death), even under
    # 'python -O' (validation is not assert-based).
    path = os.path.join(tmp, 'fund-trunc.psbt')
    open(path, 'wb').write(b'psbt\xff' + vt.vi(1) + b'\x00' + vt.vi(3) +
                           b'\x01\x02\x03' + b'\x00' + b'\x00')
    r = run_app(policy, path, os.path.join(tmp, 'tree-trunc'))
    ok('truncated PSBT refused cleanly',
       r.returncode != 0 and 'Traceback' not in (r.stdout + r.stderr) and
       'malformed PSBT' in (r.stdout + r.stderr))


def test_dust(tmp, spk_v):
    # HA-4 (audit #2): the device's W-04 check refuses to co-sign dust
    # outputs (< 546 sats) at SPEND time. A ladder whose highest-fee
    # leaf output is dust would enroll fine but be dead when needed -
    # the host must refuse to build it. Also covers a dust vault value.
    def small_funding(path, value):
        ins = [(hashlib.sha256(b'fund:dust').digest(), 0, 0xFFFFFFFE)]
        tx = vt.ser_tx(2, ins, [], 0)
        wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), value)
        im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
        open(path, 'wb').write(vt.build_psbt(tx, [im], 0))
        return path

    # leaf ladder 500/600/700 on a 1000-sat vault -> outputs 500/400/300
    fund = small_funding(os.path.join(tmp, 'fund-dust.psbt'), 1200)
    pol = make_policy(tmp, name='policy-dust.json')
    d = json.loads(open(pol).read())
    d.update({'deposit_fee': 200, 'leaves': 3, 'emg_fee': 500,
              'emg_step': 100})
    open(pol, 'w').write(json.dumps(d))
    r = run_app(pol, fund, os.path.join(tmp, 'tree-dust'))
    ok('dust leaf ladder refused',
       r.returncode != 0 and 'dust limit' in (r.stdout + r.stderr))

    # dust vault value outright
    fund2 = small_funding(os.path.join(tmp, 'fund-dust2.psbt'), 600)
    r = run_app(pol, fund2, os.path.join(tmp, 'tree-dust2'))
    ok('dust vault value refused',
       r.returncode != 0 and 'dust limit' in (r.stdout + r.stderr))

    # a sane ladder above the floor still builds
    fund3 = small_funding(os.path.join(tmp, 'fund-ok.psbt'), 100000)
    r = run_app(pol, fund3, os.path.join(tmp, 'tree-dustok'))
    ok('above-dust ladder still builds', r.returncode == 0)


def test_stale_outdir(tmp, policy, spk_v):
    # HA-5 (audit #2): rebuilding with FEWER leaves into the same outdir
    # used to leave the old emg3/emg4... files on disk - absent from the
    # new manifest, uncovered by the new lattice root, but still
    # policy-valid spends. The rebuild must clean them (and say so).
    fund = make_funding(tmp, 'input-only', spk_v, 'fund-stale')
    outdir = os.path.join(tmp, 'tree-stale')
    r = run_app(policy, fund, outdir)                 # 5 leaves
    ok('stale test: first build (5 leaves)', r.returncode == 0)
    open(os.path.join(outdir, 'unrelated.txt'), 'w').write('keep me')
    pol3 = make_policy(tmp, leaves=3, name='policy-3.json')
    r = run_app(pol3, fund, outdir)                   # rebuild w/ 3
    ok('stale test: rebuild (3 leaves)', r.returncode == 0)
    man = json.loads(open(os.path.join(outdir, 'manifest.json')).read())
    files = sorted(f for f in os.listdir(outdir) if f.endswith('.psbt'))
    ok('stale emg leaves removed',
       files == ['deposit.psbt', 'emg0.psbt', 'emg1.psbt', 'emg2.psbt']
       and man['files'] == ['emg0.psbt', 'emg1.psbt', 'emg2.psbt'])
    ok('unrelated files kept',
       os.path.exists(os.path.join(outdir, 'unrelated.txt')))
    ok('stale removal warned',
       'stale' in (r.stdout + r.stderr))


def test_min_relay_warning(tmp, spk_v):
    # HA-7 (audit #2): in the modes where the host fixes the deposit
    # fee, a fee below a conservative min-relay floor must at least be
    # warned about (the signed deposit may not relay).
    fund = make_funding(tmp, 'input-only', spk_v, 'fund-relay')
    pol = make_policy(tmp, name='policy-relay.json')
    d = json.loads(open(pol).read())
    d['deposit_fee'] = 10                            # way below floor
    open(pol, 'w').write(json.dumps(d))
    r = run_app(pol, fund, os.path.join(tmp, 'tree-relay'))
    ok('low deposit fee warned',
       r.returncode == 0 and 'min-relay' in r.stdout)
    # already-correct funding carries the funder's own fee: no warning
    fund2 = make_funding(tmp, 'correct', spk_v, 'fund-relay2')
    r = run_app(make_policy(tmp, name='policy-relay2.json'), fund2,
                os.path.join(tmp, 'tree-relay2'))
    ok('no min-relay warning when fee is the funder\'s',
       r.returncode == 0 and 'min-relay' not in r.stdout)


def test_marker_txid(tmp, policy, spk_v):
    # HA-8 (audit #2): a non-compliant producer that leaves the witness
    # marker/flag in the global tx must not corrupt the deposit txid
    # (txid excludes marker/witness). The host commits to the clean
    # serialization; leaves must spend the REAL outpoint.
    ins = [(hashlib.sha256(b'fund:marker').digest(), 0, 0xFFFFFFFE)]
    outs = [(spk_v, FUNDING_VALUE - DEPOSIT_FEE)]
    clean = vt.ser_tx(2, ins, outs, 0)
    raw = clean[:4] + b'\x00\x01' + clean[4:]        # marker + flag
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
    path = os.path.join(tmp, 'fund-marker.psbt')
    open(path, 'wb').write(vt.build_psbt(raw, [im], 1))
    outdir = os.path.join(tmp, 'tree-marker')
    r = run_app(policy, path, outdir)
    ok('marker-tx funding accepted (cleaned)', r.returncode == 0)
    if r.returncode == 0:
        man = json.loads(open(os.path.join(outdir, 'manifest.json')).read())
        ok('deposit txid is the CLEAN tx txid',
           man['deposit_txid'] == vt.txid_of(clean)[::-1].hex())
        dep = vt.parse_psbt(open(os.path.join(outdir, 'deposit.psbt'),
                                 'rb').read())
        ok('deposit global tx has no witness marker',
           dep['tx'] == clean)
        p = vt.parse_psbt(open(os.path.join(outdir, man['files'][0]),
                               'rb').read())
        _, pins, _, _ = vt.parse_tx(p['tx'])
        ok('leaf spends the real (clean-txid) outpoint',
           pins[0][0] == vt.txid_of(clean))


def test_policy_validation(tmp, spk_v):
    # HA-9 (audit #2): a malformed policy file must be refused with a
    # clear message, not a KeyError/ValueError traceback.
    fund = make_funding(tmp, 'input-only', spk_v, 'fund-badpol')
    base = json.loads(open(make_policy(tmp, name='p-base.json')).read())

    d = dict(base); del d['k3']
    p1 = os.path.join(tmp, 'p-nok3.json'); open(p1, 'w').write(json.dumps(d))
    r = run_app(p1, fund, os.path.join(tmp, 'tree-nok3'))
    ok('missing policy field refused',
       r.returncode != 0 and 'k3' in (r.stdout + r.stderr) and
       'Traceback' not in (r.stdout + r.stderr))

    d = dict(base); d['k2'] = 'zz' * 33
    p2 = os.path.join(tmp, 'p-badhex.json'); open(p2, 'w').write(json.dumps(d))
    r = run_app(p2, fund, os.path.join(tmp, 'tree-badhex'))
    ok('non-hex policy key refused',
       r.returncode != 0 and 'not valid hex' in (r.stdout + r.stderr))

    d = dict(base); d['k2'] = base['k1']             # duplicate pubkey
    p3 = os.path.join(tmp, 'p-dupkey.json'); open(p3, 'w').write(json.dumps(d))
    r = run_app(p3, fund, os.path.join(tmp, 'tree-dupkeypol'))
    ok('duplicate-pubkey policy refused (quorum collapse)',
       r.returncode != 0 and 'quorum' in (r.stdout + r.stderr) and
       'Traceback' not in (r.stdout + r.stderr))

    d = dict(base); d['leaves'] = 20; d['emg_fee'] = 999; d['emg_step'] = 500
    p4 = os.path.join(tmp, 'p-hifee.json'); open(p4, 'w').write(json.dumps(d))
    r = run_app(p4, fund, os.path.join(tmp, 'tree-hifee'))
    ok('leaf fee above f0_max refused at load',
       r.returncode != 0 and 'f0_max' in (r.stdout + r.stderr))

    open(os.path.join(tmp, 'p-notjson.json'), 'w').write('{nope')
    r = run_app(os.path.join(tmp, 'p-notjson.json'), fund,
                os.path.join(tmp, 'tree-notjson'))
    ok('non-JSON policy refused',
       r.returncode != 0 and 'not valid JSON' in (r.stdout + r.stderr))


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
        test_dup_key(tmp, policy, spk_v)
        test_truncated(tmp, policy, spk_v)
        test_dust(tmp, spk_v)
        test_stale_outdir(tmp, policy, spk_v)
        test_min_relay_warning(tmp, spk_v)
        test_marker_txid(tmp, policy, spk_v)
        test_policy_validation(tmp, spk_v)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(1 for _, c in R if c)
    print('VAULT HOSTAPP: %d/%d checks pass' % (n, len(R)))
    if n != len(R):
        sys.exit(1)

if __name__ == '__main__':
    main()
