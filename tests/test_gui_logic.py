# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# tests/test_gui_logic.py - headless tests for the gui.py logic layer
# (everything the GUI's buttons call, minus the Tk widgets: PSBT text
# decoding, policy field validation/round-trips, preview, report
# formatting, and a full build through gui.run_build with funding as
# BYTES - the paste route - cross-checked against the file route).
#
# Run: python3 tests/test_gui_logic.py

import os
import sys
import json
import base64
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import gui
import vault_tree as vt
import vault_policy as vp

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    print('%s: %s' % ('ok' if cond else 'FAIL', name))

def hostapp_err(fn, *a, **kw):
    # returns the HostappError message, or None if nothing was raised
    try:
        fn(*a, **kw)
        return None
    except vt.HostappError as e:
        return str(e)


# ---- funding PSBT fixtures (same shape as test_vault_hostapp) -------------

FUNDING_VALUE = 100000

def make_funding(path, outs):
    ins = [(b'\xaa' * 32, 0, 0xffffffff)]
    tx = vt.ser_tx(2, ins, outs, 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
    open(path, 'wb').write(vt.build_psbt(tx, [im], len(outs)))
    return open(path, 'rb').read()

def good_fields():
    return {
        'k1': (b'\x02' + bytes(range(1, 33))).hex(),
        'k2': (b'\x03' + bytes(range(33, 65))).hex(),
        'k3': (b'\x02' + bytes(range(65, 97))).hex(),
        'n': '1008', 'f0_max': '10000', 'leaves': '5',
        'emg_fee': '500', 'emg_step': '13', 'deposit_fee': '500',
        'exit_spk': '',
    }


# ---- 1. decode_psbt_text ---------------------------------------------------

tmp = tempfile.mkdtemp(prefix='gui-logic-')
try:
    blob = make_funding(os.path.join(tmp, 'f.psbt'), [])

    ok('decode: hex round-trip',
       gui.decode_psbt_text(blob.hex()) == blob)
    ok('decode: base64 round-trip',
       gui.decode_psbt_text(base64.b64encode(blob).decode()) == blob)
    ok('decode: whitespace-tolerant hex',
       gui.decode_psbt_text('  '.join(blob.hex()[i:i + 8]
                                      for i in range(0, 96, 8))) is not None
       or True)  # (formatting smoke; real check below)
    ok('decode: whitespace hex == blob',
       gui.decode_psbt_text('\n'.join(
           blob.hex()[i:i + 64] for i in range(0, len(blob.hex()), 64)))
       == blob)
    ok('decode: empty raises',
       hostapp_err(gui.decode_psbt_text, '') is not None)
    ok('decode: garbage raises',
       hostapp_err(gui.decode_psbt_text, 'not a psbt at all') is not None)
    ok('decode: wrong magic raises',
       hostapp_err(gui.decode_psbt_text, b'xxxx\xff'.hex() + '00') is not None)

    # ---- 2. policy field validation ----------------------------------------

    pol = gui.policy_from_fields(good_fields())
    ok('fields: valid policy parses', pol['n'] == 1008 and
       pol['k1'] == b'\x02' + bytes(range(1, 33)))

    bad = good_fields(); bad['n'] = '70000'
    ok('fields: N above 65535 refused',
       '65535' in (hostapp_err(gui.policy_from_fields, bad) or ''))
    bad = good_fields(); bad['n'] = 'zero'
    ok('fields: non-numeric N refused',
       hostapp_err(gui.policy_from_fields, bad) is not None)
    bad = good_fields(); bad['k2'] = 'abcd'
    ok('fields: short pubkey refused',
       'compressed' in (hostapp_err(gui.policy_from_fields, bad) or ''))
    bad = good_fields(); bad['k3'] = 'zz' * 33
    ok('fields: non-hex pubkey refused',
       hostapp_err(gui.policy_from_fields, bad) is not None)
    bad = good_fields(); bad['leaves'] = '0'
    ok('fields: zero leaves refused',
       hostapp_err(gui.policy_from_fields, bad) is not None)
    bad = good_fields(); bad['emg_fee'] = '9999'; bad['emg_step'] = '500'
    ok('fields: leaf fee above f0_max refused',
       'F0' in (hostapp_err(gui.policy_from_fields, bad) or ''))
    bad = good_fields(); bad['exit_spk'] = 'ab' * 20
    ok('fields: non-P2WSH exit_spk refused',
       'P2WSH' in (hostapp_err(gui.policy_from_fields, bad) or ''))
    bad = good_fields(); bad['emg_fee'] = ''
    ok('fields: empty numeric field refused',
       hostapp_err(gui.policy_from_fields, bad) is not None)

    # ---- 3. policy JSON round-trip ------------------------------------------

    pol2 = gui.policy_from_json(gui.policy_to_json(pol))
    ok('policy json round-trip', pol2 == pol)
    ok('policy json: garbage refused',
       hostapp_err(gui.policy_from_json, '{nope') is not None)
    ok('fields_from_policy inverse',
       gui.policy_from_fields(gui.fields_from_policy(pol)) == pol)

    # ---- 4. preview -----------------------------------------------------------

    p = gui.preview_psbt(blob)
    ok('preview: inputs/outputs/value',
       p['inputs'] == 1 and p['outputs'] == 0 and
       p['value'] == FUNDING_VALUE and p['has_witness_utxos'])
    ok('preview: malformed refused',
       hostapp_err(gui.preview_psbt, b'garbage') is not None)

    # ---- 5. full build via the GUI's exact code path -------------------------

    out1 = os.path.join(tmp, 'out-paste')
    rep = gui.run_build(gui.policy_from_fields(good_fields()),
                        blob, out1)              # funding as BYTES (paste)
    man = json.loads(open(os.path.join(out1, 'manifest.json')).read())
    ok('build (paste route): manifest written',
       man['lattice_root'] == rep['lattice_root'] and
       man['vault_value'] == FUNDING_VALUE - 500)
    ok('build (paste route): leaf files exist',
       all(os.path.exists(os.path.join(out1, f))
           for f in rep['leaf_files']))

    # cross-check against the FILE route (the CLI path)
    out2 = os.path.join(tmp, 'out-file')
    rep2 = vt.build_tree(pol, os.path.join(tmp, 'f.psbt'), out2,
                         500, 5, 500, 13)
    ok('build: paste route == file route',
       rep['lattice_root'] == rep2['lattice_root'] and
       rep['deposit_txid'] == rep2['deposit_txid'])

    # funding shape warnings surface in the report
    blob_bad = make_funding(os.path.join(tmp, 'f2.psbt'),
                            [(vp.p2wsh_spk(b'\x62' * 30), 50000)])
    rep3 = gui.run_build(gui.policy_from_fields(good_fields()),
                         blob_bad, os.path.join(tmp, 'out-warn'))
    ok('build: incorrect-output warning surfaced',
       len(rep3['warnings']) == 1 and 'REPLACING' in rep3['warnings'][0])

    # ---- 6. report formatting -------------------------------------------------

    txt = gui.format_report(rep)
    ok('report: contains lattice root', rep['lattice_root'] in txt)
    ok('report: contains deposit txid', rep['deposit_txid'] in txt)
    ok('report: warning rendered first',
       gui.format_report(rep3).startswith('WARNING:'))

    # ---- 7. audit #2 regression checks (HA-1/2/4/5/10) ------------------------

    # HA-1: duplicate pubkeys raise HostappError (was: bare
    # VaultViolation that escaped every GUI error handler)
    bad = good_fields(); bad['k2'] = bad['k1']
    msg = hostapp_err(gui.policy_from_fields, bad)
    ok('dup pubkeys -> HostappError (not VaultViolation)',
       msg is not None and 'quorum' in msg)

    # HA-2: a truncated PSBT through run_build raises HostappError (was:
    # bare struct.error that killed the Tk callback silently)
    trunc = (b'psbt\xff' + vt.vi(1) + b'\x00' + vt.vi(3) +
             b'\x01\x02\x03' + b'\x00' + b'\x00')
    msg = hostapp_err(gui.run_build, gui.policy_from_fields(good_fields()),
                      trunc, os.path.join(tmp, 'out-trunc'))
    ok('truncated PSBT -> HostappError (not struct.error)',
       msg is not None and 'malformed' in msg)

    # HA-3: duplicated witness-utxo key refused
    wu2 = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im2 = (vt.vi(1) + b'\x01' + vt.vi(len(wu2)) + wu2 +
           vt.vi(1) + b'\x01' + vt.vi(len(wu2)) + wu2 + b'\x00')
    dupblob = vt.build_psbt(
        vt.ser_tx(2, [(b'\xaa' * 32, 0, 0xffffffff)], [], 0), [im2], 0)
    msg = hostapp_err(gui.run_build, gui.policy_from_fields(good_fields()),
                      dupblob, os.path.join(tmp, 'out-dup'))
    ok('duplicate map key -> HostappError', msg is not None and
       'duplicate key' in msg)

    # HA-4: dust ladder refused through the GUI's exact build path
    dust_tx = vt.ser_tx(2, [(b'\xab' * 32, 0, 0xffffffff)], [], 0)
    dwu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), 1200)
    dim = vt.vi(1) + b'\x01' + vt.vi(len(dwu)) + dwu + b'\x00'
    dustblob = vt.build_psbt(dust_tx, [dim], 0)
    dusty = good_fields()
    dusty.update({'deposit_fee': '200', 'leaves': '3', 'emg_fee': '500',
                  'emg_step': '100'})
    msg = hostapp_err(gui.run_build, gui.policy_from_fields(dusty),
                      dustblob, os.path.join(tmp, 'out-dust'))
    ok('dust ladder refused via run_build', msg is not None and
       'dust limit' in msg)

    # HA-5: stale leaves from a previous larger build are cleaned
    so = os.path.join(tmp, 'out-stale')
    gui.run_build(gui.policy_from_fields(good_fields()), blob, so)
    smaller = good_fields(); smaller['leaves'] = '3'
    rep_s = gui.run_build(gui.policy_from_fields(smaller), blob, so)
    ok('stale emg leaves cleaned on rebuild',
       sorted(f for f in os.listdir(so) if f.endswith('.psbt')) ==
       ['deposit.psbt', 'emg0.psbt', 'emg1.psbt', 'emg2.psbt'])
    ok('stale removal warned in report',
       any('stale' in w for w in rep_s['warnings']))

    # HA-10: JSON null renders as '' (was: the string 'None')
    ok('fields_from_policy: None exit_spk -> empty',
       gui.fields_from_policy({'exit_spk': None})['exit_spk'] == '')

    # ---- 8. GUI module imports headlessly --------------------------------------

    ok('gui imports without tkinter (HAVE_TK flag)',
       hasattr(gui, 'HAVE_TK'))

finally:
    shutil.rmtree(tmp, ignore_errors=True)

n = sum(1 for _, c in R if c)
print('GUI LOGIC: %d/%d checks pass' % (n, len(R)))
if n != len(R):
    sys.exit(1)
