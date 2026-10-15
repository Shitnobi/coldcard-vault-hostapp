#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# vault_tree.py - the host side of the vault protocol (CLI; see gui.py
# for the graphical front end).
#
# Accepts a FUNDING PSBT in one of three shapes:
#   1. "just the input": one or more inputs (witness utxos) and no outputs
#   2. input(s) with an INCORRECT output: outputs exist but none pays the
#      vault script S_v with the right value -> warned and replaced
#   3. already-correct: an output pays S_v -> accepted as the deposit as-is
#
# and constructs the vault PSBT tree from it:
#   deposit.psbt     funding -> S_v (P2WSH of the branched vault script)
#   emg<i>.psbt      pre-authorized emergency exits S_v -> S_e (the lattice
#                    leaves; what gets enrolled on the Coldcard)
#   manifest.json    device-enrollment cfg + host lattice root (compare
#                    against the root the device displays at enrollment)
#
# The rule layer (script shapes, leaf hashing, Merkle root) is imported from
# shared/vault_policy.py so host and device agree by construction.
#
# Usage:
#   python3 vault_tree.py init-policy policy.json
#   python3 vault_tree.py build policy.json funding.psbt outdir/
#       [--deposit-fee 500] [--leaves 5] [--emg-fee 500] [--emg-step 13]

import os, sys, json, hashlib, struct, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
# vault_policy.py lives next to this file in this standalone repo (it is
# the pure policy/rule core the device firmware also uses - host and
# device agree by construction). In the original firmware tree it lives
# in shared/ and is appended to sys.path here.
sys.path.append(HERE)
import vault_policy as vp

SEQ_EMERGENCY = vp.SEQ_EMERGENCY


class HostappError(SystemExit):
    # Fatal, user-facing error. Subclasses SystemExit so the CLI keeps
    # its exact historical behavior (message to stderr, exit code 1,
    # 'except SystemExit' in tests) while the GUI can catch it.
    pass


# ---- minimal host-side PSBT / tx codec (BIP-174 v0, witness-utxo form) ---

def vi(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b'\xfd' + struct.pack('<H', n)
    assert n < 0x100000000, 'value too large for this basic app'
    return b'\xfe' + struct.pack('<I', n)


def read_vi(b, p):
    c = b[p]
    p += 1
    if c < 253:
        return c, p
    if c == 253:
        return struct.unpack('<H', b[p:p + 2])[0], p + 2
    if c != 0xfe:
        raise HostappError('varint too large for this basic app')
    return struct.unpack('<I', b[p:p + 4])[0], p + 4


def parse_tx(b):
    # legacy unsigned tx: empty scriptSigs assumed. Returns
    # (version, ins[(txid,n,seq)], outs[(spk,value)], locktime)
    version, p = struct.unpack('<i', b[:4])[0], 4
    marker = b[p] if len(b) > p + 1 else 1
    if marker == 0:                      # stray witness marker: skip it
        p += 2
    nin, p = read_vi(b, p)
    ins = []
    for _ in range(nin):
        txid, n = b[p:p + 32], struct.unpack('<I', b[p + 32:p + 36])[0]
        p += 36
        slen, p = read_vi(b, p)
        if slen != 0:
            raise HostappError('scriptSig not empty in unsigned tx')
        seq = struct.unpack('<I', b[p:p + 4])[0]
        p += 4
        ins.append((txid, n, seq))
    nout, p = read_vi(b, p)
    outs = []
    for _ in range(nout):
        val = struct.unpack('<q', b[p:p + 8])[0]
        p += 8
        slen, p = read_vi(b, p)
        outs.append((b[p:p + slen], val))
        p += slen
    locktime = struct.unpack('<I', b[p:p + 4])[0]
    return version, ins, outs, locktime


def ser_tx(version, ins, outs, locktime):
    r = struct.pack('<i', version) + vi(len(ins))
    for (txid, n, seq) in ins:
        r += txid + struct.pack('<I', n) + vi(0) + struct.pack('<I', seq)
    r += vi(len(outs))
    for (spk, val) in outs:
        r += struct.pack('<q', val) + vi(len(spk)) + spk
    return r + struct.pack('<I', locktime)


def txid_of(raw_tx):
    return hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()


def parse_psbt(blob):
    # Returns {tx: bytes, in_maps: [raw input-map bytes], wutxos: [(spk,val)]}
    #
    # Audit #2 hardening:
    #   HA-3: BIP-174 forbids duplicate keys within a map. A duplicated
    #     0x01 witness-utxo key used to be read twice, inflating total_in
    #     (and so the built vault value). Duplicate keys are now refused.
    #   HA-2/HA-13: structural failures raise HostappError (not assert),
    #     so malformed input is refused even under 'python -O' and the
    #     GUI can surface it as a dialog instead of dying silently.
    if blob[:5] != b'psbt\xff':
        raise HostappError('not a PSBT (missing magic)')
    p = 5
    tx = None
    try:
        while True:                               # globals map
            ks, p = read_vi(blob, p)
            if ks == 0:
                break
            key = blob[p:p + ks]
            p += ks
            vs, p = read_vi(blob, p)
            val = blob[p:p + vs]
            p += vs
            if key == b'\x00':
                if tx is not None:
                    raise HostappError('duplicate UNSIGNED_TX in globals')
                tx = val
        if tx is None:
            raise HostappError('no UNSIGNED_TX in globals')
        _, ins, outs, _ = parse_tx(tx)

        in_maps, wutxos = [], []
        for mi in range(len(ins)):                 # one map per input
            start = p
            seen = set()
            while True:
                ks, p = read_vi(blob, p)
                if ks == 0:
                    break
                key = blob[p:p + ks]
                p += ks
                if key in seen:
                    raise HostappError('duplicate key %s in input map %d '
                                       '(BIP-174 forbids duplicate map '
                                       'keys)' % (key.hex(), mi))
                seen.add(key)
                vs, p = read_vi(blob, p)
                val = blob[p:p + vs]
                p += vs
                if key == b'\x01':                 # PSBT_IN_WITNESS_UTXO
                    # BIP-174: this key has no key data; keys of the form
                    # '01 <data>' are unknown keys (passed through verbatim
                    # via in_maps) and must NOT be read as utxos.
                    # CTxOut: value LE64 + varstring spk
                    v = struct.unpack('<q', val[:8])[0]
                    slen, q = read_vi(val, 8)
                    wutxos.append((val[q:q + slen], v))
            in_maps.append(blob[start:p])

        for oi in range(len(outs)):                # one map per output
            seen = set()
            while True:
                ks, p = read_vi(blob, p)
                if ks == 0:
                    break
                key = blob[p:p + ks]
                p += ks
                if key in seen:
                    raise HostappError('duplicate key %s in output map %d '
                                       '(BIP-174 forbids duplicate map '
                                       'keys)' % (key.hex(), oi))
                seen.add(key)
                vs, p = read_vi(blob, p)
                p += vs
    except (IndexError, struct.error) as e:
        # truncated / short-read blobs (HostappError is SystemExit and
        # never caught here)
        raise HostappError('malformed PSBT (truncated): %s' % e)
    if p != len(blob):
        raise HostappError('PSBT map count/length mismatch')
    return {'tx': tx, 'in_maps': in_maps, 'wutxos': wutxos,
            'ins': ins, 'outs': outs}


def build_psbt(tx_bytes, in_maps, num_outputs):
    r = b'psbt\xff'
    r += vi(1) + b'\x00' + vi(len(tx_bytes)) + tx_bytes
    r += b'\x00'                                  # end globals
    for m in in_maps:
        r += m                                    # verbatim (has separator)
    for _ in range(num_outputs):
        r += b'\x00'                              # empty output maps
    return r


def ct_out(spk, value):
    return struct.pack('<q', value) + vi(len(spk)) + spk


# ---- policy -> scripts ----------------------------------------------------

def push_num(n):
    # Data-push encoding of the cadence N, padded so the script-num is
    # always positive (a push whose last byte has the sign bit set, e.g.
    # '01 C8' for N=200, is a NEGATIVE script number and is refused by
    # parse_vault_script).
    # NOTE: parse_vault_script requires a data push (not OP_1..OP_16), so
    # N <= 16 is intentionally encoded non-minimally.
    if not (1 <= n <= 0xFFFF):
        raise HostappError('ERROR: cadence N must be in 1..65535, got %d' % n)
    payload = n.to_bytes((n.bit_length() + 7) // 8, 'little')
    if payload[-1] & 0x80:
        payload += b'\x00'        # keep the script-num positive
    return bytes([len(payload)]) + payload


def build_scripts(pol):
    # S_v (D-1'): OP_IF <N> OP_CSV OP_DROP OP_ELSE OP_ENDIF
    #             OP_2 <K1> <K2> <K3> OP_3 OP_CHECKMULTISIG
    # S_e (E-2):  <K1> OP_CHECKSIGVERIFY OP_1 <K2> <K3> OP_2 OP_CMS (106 B)
    def push(b):
        return bytes([len(b)]) + b
    k1, k2, k3 = pol['k1'], pol['k2'], pol['k3']
    n = pol['n']
    n_push = push_num(n)
    s_v = (bytes([vp.OP_IF]) + n_push +
           bytes([vp.OP_CSV, vp.OP_DROP, vp.OP_ELSE, vp.OP_ENDIF, 0x52]) +
           push(k1) + push(k2) + push(k3) + bytes([0x53, vp.OP_CMS]))
    s_e = (push(k1) + bytes([vp.OP_CHECKSIGVERIFY, 0x51]) + push(k2) +
           push(k3) + bytes([0x52, vp.OP_CMS]))
    assert len(s_e) == 106, 'S_e must be 106 bytes'
    # structural self-checks against the same parser the device uses
    assert vp.parse_vault_script(s_v)['n'] == n
    vp.parse_deepvault_script(s_e)
    return s_v, s_e


def cfg_from_policy(pol, s_v, s_e):
    # exit destinations are confined to P2WSH (VaultPolicy shape check
    # on-device); refuse a non-P2WSH override here too, with a clearer
    # message than the device's 'bad policy' enrollment refusal
    ex = pol.get('exit_spk')
    if ex:
        b = bytes.fromhex(ex)
        if len(b) != 34 or b[:2] != b'\x00\x20':
            raise HostappError(
                'ERROR: exit_spk must be a P2WSH scriptPubKey '
                '(34 bytes: OP_0 PUSH32 <hash>), got %d-byte spk %s'
                % (len(b), ex))
    return {
        'n': pol['n'],
        'sv_hash': vp.p2wsh_spk(s_v).hex(),
        'spk_e': vp.p2wsh_spk(s_e).hex(),
        'k1_pubkey': pol['k1'].hex(),
        'f0_max': pol['f0_max'],
        'exit_spk': pol.get('exit_spk') or
                    vp.p2wsh_spk(bytes([0x51]) + pol['k1'] + pol['k2'] +
                                 pol['k3'] + bytes([vp.OP_CMS])).hex(),
    }


# ---- the app ---------------------------------------------------------------

def load_funding(funding, spk_v, deposit_fee):
    # Accept, classify and normalize the funding PSBT. `funding` is a
    # file path (str) or the raw PSBT bytes (e.g. decoded from pasted
    # hex/base64 by the GUI). Returns
    # (mode, tx_bytes, in_maps, vault_value, total_in, vault_vout,
    #  warnings) - warnings is a list of human-readable strings the
    # caller (CLI print / GUI display) surfaces to the user.
    blob = open(funding, 'rb').read() if isinstance(funding, str) else funding
    ps = parse_psbt(blob)
    warnings = []
    if not ps['wutxos']:
        raise HostappError('ERROR: funding PSBT needs witness utxos')
    total_in = sum(v for _, v in ps['wutxos'])
    if total_in <= deposit_fee:
        raise HostappError('ERROR: funding value (%d) <= deposit fee (%d)'
                           % (total_in, deposit_fee))
    version, ins, outs, locktime = parse_tx(ps['tx'])

    match = [i for i, (spk, val) in enumerate(outs) if spk == spk_v]
    # vout of the deposit output paying S_v: 0 in the rebuilt shapes,
    # but the funding's own index when accepted verbatim
    vault_vout = 0
    if not outs:
        mode = 'input-only'
    elif match:
        if len(match) != 1:
            # ambiguous: only one output may pay S_v (which one is the
            # deposit?); refuse rather than guess
            raise HostappError('ERROR: %d outputs pay S_v (expected exactly '
                               'one); ambiguous funding refused' % len(match))
        if outs[match[0]][1] != total_in - deposit_fee:
            mode = 'incorrect-output'
        elif sum(v for _, v in outs) > total_in:
            raise HostappError('ERROR: funding outputs (%d sats) exceed '
                               'inputs (%d sats)' %
                               (sum(v for _, v in outs), total_in))
        else:
            mode = 'already-correct'
            vault_vout = match[0]
    else:
        mode = 'incorrect-output'

    if mode == 'already-correct':
        # HA-8 (audit #2): commit to the CLEAN serialization of the
        # funding tx, not the raw global-tx bytes. A non-compliant
        # producer that left a witness marker/flag in the global tx
        # would otherwise yield a wrong txid (txid excludes marker and
        # witness data) and every leaf would spend a nonexistent
        # outpoint. Byte-identical to ps['tx'] for compliant PSBTs.
        tx_bytes = ser_tx(version, ins, outs, locktime)
        vault_value = outs[match[0]][1]
    else:
        if mode == 'incorrect-output':
            warnings.append(
                'funding output does not pay S_v with value '
                'funding-fee; REPLACING all outputs (incl. any change) '
                'with the vault deposit')
        vault_value = total_in - deposit_fee
        tx_bytes = ser_tx(version, ins, [(spk_v, vault_value)], locktime)
    return (mode, tx_bytes, ps['in_maps'], vault_value, total_in,
            vault_vout, warnings)


def build_tree(pol, funding_path, outdir, deposit_fee, leaves,
               emg_fee, emg_step):
    # Build the full vault tree (deposit + emergency lattice + manifest)
    # and return a report dict for the caller to render (CLI prints it,
    # the GUI shows it in the results pane). `funding_path` is a file
    # path or raw PSBT bytes.
    s_v, s_e = build_scripts(pol)
    spk_v, spk_e = vp.p2wsh_spk(s_v), vp.p2wsh_spk(s_e)
    cfg = cfg_from_policy(pol, s_v, s_e)

    (mode, dep_tx, in_maps, vault_value, total_in, vault_vout, warnings
     ) = load_funding(funding_path, spk_v, deposit_fee)

    # HA-4 (audit #2): dust floor. The device's W-04 check refuses to
    # co-sign any output below DUST_LIMIT - at SPEND time, long after
    # enrollment. Refuse here instead, so a dust ladder can never be
    # built+enrolled only to be discovered dead when it is needed.
    hi_fee = emg_fee + (leaves - 1) * emg_step
    if vault_value < vp.DUST_LIMIT:
        raise HostappError(
            'ERROR: vault value %d sats is below the dust limit %d - '
            'the deposit output would be non-standard' %
            (vault_value, vp.DUST_LIMIT))
    if vault_value - hi_fee < vp.DUST_LIMIT:
        raise HostappError(
            'ERROR: highest-fee leaf output %d sats is below the dust '
            'limit %d (vault %d - fee %d); the device would refuse to '
            'co-sign it - lower the emergency fees or fund more' %
            (vault_value - hi_fee, vp.DUST_LIMIT, vault_value, hi_fee))

    os.makedirs(outdir, exist_ok=True)
    # HA-5 (audit #2): remove stale artifacts from a previous (e.g.
    # larger) build in this outdir. Leftover emg*.psbt files are absent
    # from the new manifest and NOT covered by the new lattice root,
    # but remain policy-valid spends a user could still pick at
    # enrollment. Only our own output names are touched.
    stale = sorted(
        f for f in os.listdir(outdir)
        if f in ('deposit.psbt', 'manifest.json') or
        (f.startswith('emg') and f.endswith('.psbt')))
    for f in stale:
        os.remove(os.path.join(outdir, f))
    if stale:
        warnings.append('removed %d stale file(s) from a previous build: '
                        '%s' % (len(stale), ', '.join(stale)))

    # deposit.psbt: funding -> S_v (input maps carried over verbatim; one
    # output map per output of the deposit tx)
    version, dep_ins, dep_outs, locktime = parse_tx(dep_tx)
    # HA-7 (audit #2): min-relay floor on the deposit fee, mirroring the
    # device-side _min_relay_fee conservatism. Only meaningful in the
    # modes where WE fix the deposit's fee (already-correct funding
    # carries the funder's own implicit fee).
    if mode != 'already-correct':
        floor = 100 + 70 * len(dep_ins) + 45 * len(dep_outs)
        if deposit_fee < floor:
            warnings.append(
                'deposit fee %d sats is below a conservative min-relay '
                'floor of %d for a %d-input deposit; the signed deposit '
                'may not relay' % (deposit_fee, floor, len(dep_ins)))
    deposit = build_psbt(dep_tx, in_maps, len(dep_outs))
    open(os.path.join(outdir, 'deposit.psbt'), 'wb').write(deposit)

    dep_txid = txid_of(dep_tx)

    # the lattice: pre-authorized emergency exits spending the vault UTXO
    # (deposit vout `vault_vout` - NOT always 0: an already-correct
    # funding tx may carry other outputs before the vault output)
    # leaf names are zero-padded to a fixed width so that the device
    # file-picker's lexicographic sort order == the numeric leaf order.
    files = []
    leaf_txs = []
    leaf_w = len(str(leaves - 1)) if leaves > 1 else 1
    for i in range(leaves):
        fee = emg_fee + i * emg_step
        if not (0 < fee <= pol['f0_max']):
            raise HostappError('ERROR: emg fee %d outside (0, f0_max=%d]'
                               % (fee, pol['f0_max']))
        if fee >= vault_value:
            raise HostappError('ERROR: emg fee %d >= vault value %d'
                               % (fee, vault_value))
        # vault txs commit nLockTime == 0 (REV3 5.3) - not inherited
        # from the funding tx
        tx = ser_tx(version, [(dep_txid, vault_vout, SEQ_EMERGENCY)],
                    [(spk_e, vault_value - fee)], 0)
        wu = ct_out(spk_v, vault_value)
        # The leaf input map must carry everything the Coldcard needs to
        # verify + enroll the leaf (found by running a hostapp-built tree
        # through the real device simulator):
        #   0x01 witness utxo      - the vault coin (spk_v, vault_value)
        #   0x05 witness script    - S_v itself (recognize() + partial-sig
        #                            verification need the actual script)
        #   0x00 full (non-witness) UTXO - the deposit tx, for the P1
        #                            fee-window txid cross-check
        im = (vi(1) + b'\x01' + vi(len(wu)) + wu +
              vi(1) + b'\x05' + vi(len(s_v)) + s_v +
              vi(1) + b'\x00' + vi(len(dep_tx)) + dep_tx +
              b'\x00')
        name = 'emg%0*d.psbt' % (leaf_w, i)
        open(os.path.join(outdir, name), 'wb').write(
            build_psbt(tx, [im], 1))
        files.append(name)
        leaf_txs.append(tx)

    root, count = vp.lattice_root(
        iter([vp.leaf_hash(i, t) for i, t in enumerate(leaf_txs)]))

    manifest = {
        'cfg': cfg,
        'lattice_root': root.hex(),
        'lattice_count': count,
        'funding_mode': mode,
        'funding_value': total_in,
        'deposit_fee': deposit_fee,
        'vault_value': vault_value,
        'vault_vout': vault_vout,
        'deposit_txid': dep_txid[::-1].hex(),     # display order
        'files': files,
        # for the unix/vault_sim_e2e.py device driver
        'expect': [[f, True, 'emergency', 'app-built emergency leaf']
                   for f in files],
    }
    open(os.path.join(outdir, 'manifest.json'), 'w').write(
        json.dumps(manifest, indent=1))

    return {
        'warnings': warnings,
        'funding_mode': mode,
        'funding_value': total_in,
        'vault_value': vault_value,
        'deposit_fee': deposit_fee,
        'vault_vout': vault_vout,
        'deposit_txid': manifest['deposit_txid'],
        'lattice_count': count,
        'leaf_files': files,
        'emg_fee': emg_fee,
        'emg_step': emg_step,
        'lattice_root': root.hex(),
        'spk_v': spk_v.hex(),
        'spk_e': spk_e.hex(),
        'outdir': os.path.abspath(outdir),
        'manifest_path': os.path.abspath(
            os.path.join(outdir, 'manifest.json')),
    }


def print_report(rep):
    # CLI rendering of a build_tree() report (same lines as the
    # historical output, plus any funding warnings surfaced first)
    for w in rep['warnings']:
        print('WARNING: %s' % w)
    print('funding mode:     %s' % rep['funding_mode'])
    print('funding value:    %d sats' % rep['funding_value'])
    print('vault value:      %d sats (deposit fee %d)' %
          (rep['vault_value'], rep['deposit_fee']))
    print('vault vout:       %d' % rep['vault_vout'])
    print('deposit txid:     %s' % rep['deposit_txid'])
    print('lattice:          %d emergency leaves, fees %d..%d' %
          (rep['lattice_count'], rep['emg_fee'],
           rep['emg_fee'] + (len(rep['leaf_files']) - 1) * rep['emg_step']))
    leaf_w = len(str(len(rep['leaf_files']) - 1)) \
        if len(rep['leaf_files']) > 1 else 1
    print('leaf files:       emg%0*d.psbt .. emg%0*d.psbt (fixed width: '
          'file-picker sort order == leaf order; ENROLL IN THAT ORDER)'
          % (leaf_w, 0, leaf_w, len(rep['leaf_files']) - 1))
    print('lattice root:     %s' % rep['lattice_root'])
    print('wrote %d emg PSBTs + deposit.psbt + manifest.json to %s' %
          (rep['lattice_count'], rep['outdir']))


def init_policy(path, random_keys):
    import secrets
    def rk():
        return bytes([0x02 if secrets.randbelow(2) else 0x03]) + \
               secrets.token_bytes(32)
    pol = {
        # NOTE: pubkeys are random 33-byte strings unless you supply real
        # ones - fine for protocol-shape testing, NOT for real funds.
        'k1': rk() if random_keys else
              b'\x02' + bytes(range(1, 33)),
        'k2': rk() if random_keys else
              b'\x03' + bytes(range(33, 65)),
        'k3': rk() if random_keys else
              b'\x02' + bytes(range(65, 97)),
        'n': 1008,
        'f0_max': 10000,
        'leaves': 5,
        'emg_fee': 500,
        'emg_step': 13,
        'deposit_fee': 500,
    }
    open(path, 'w').write(json.dumps(
        {k: v.hex() if isinstance(v, bytes) else v for k, v in pol.items()},
        indent=1))
    print('wrote sample policy to %s' % path)


def validate_policy(pol):
    # HA-9 (audit #2): reject a malformed policy with a clear message
    # instead of a KeyError/ValueError traceback, BEFORE any output is
    # written. Optional ladder knobs default to the CLI defaults; the
    # structural script checks (duplicate-pubkey quorum collapse etc.)
    # run through the same parser the device uses.
    for k in ('k1', 'k2', 'k3'):
        b = pol.get(k)
        if not isinstance(b, bytes) or len(b) != 33 or b[0] not in (0x02,
                                                                    0x03):
            raise HostappError('ERROR: policy field %s must be a 33-byte '
                               'compressed pubkey (02/03 + 32 bytes)' % k)
    n = pol.get('n')
    if not isinstance(n, int) or not (1 <= n <= 0xFFFF):
        raise HostappError('ERROR: policy field n (cadence) must be an '
                           'integer in 1..65535')
    f0 = pol.get('f0_max')
    if not isinstance(f0, int) or f0 <= 0:
        raise HostappError('ERROR: policy field f0_max must be a positive '
                           'integer')
    leaves = pol.get('leaves', 5)
    emg_fee = pol.get('emg_fee', 500)
    emg_step = pol.get('emg_step', 13)
    for k, v, lo in (('leaves', leaves, 1), ('emg_fee', emg_fee, 1),
                     ('emg_step', emg_step, 0)):
        if not isinstance(v, int) or v < lo:
            raise HostappError('ERROR: policy field %s must be an integer '
                               '>= %d' % (k, lo))
    hi = emg_fee + (leaves - 1) * emg_step
    if hi > f0:
        raise HostappError('ERROR: highest emergency leaf fee (%d) exceeds '
                           'f0_max (%d)' % (hi, f0))
    try:
        build_scripts(pol)
    except vp.VaultViolation as e:
        raise HostappError('ERROR: policy refused: %s' % e)
    return pol


def load_policy(path):
    try:
        d = json.loads(open(path).read())
    except OSError as e:
        raise HostappError('ERROR: cannot read policy %s: %s' % (path, e))
    except ValueError as e:
        raise HostappError('ERROR: policy %s is not valid JSON: %s'
                           % (path, e))
    if not isinstance(d, dict):
        raise HostappError('ERROR: policy %s is not a JSON object' % path)
    for k in ('k1', 'k2', 'k3'):
        try:
            d[k] = bytes.fromhex(d[k])
        except (KeyError, ValueError, TypeError):
            raise HostappError('ERROR: policy field %s: not valid hex' % k)
    return validate_policy(d)


def main():
    ap = argparse.ArgumentParser(description='basic vault host app')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('init-policy', help='write a sample policy.json')
    p1.add_argument('path')
    p1.add_argument('--random-keys', action='store_true',
                    help='random demo keys (default: fixed test keys)')

    p2 = sub.add_parser('build', help='build the vault PSBT tree')
    p2.add_argument('policy')
    p2.add_argument('funding', help='funding PSBT file')
    p2.add_argument('outdir')
    p2.add_argument('--deposit-fee', type=int, default=None)
    p2.add_argument('--leaves', type=int, default=None)
    p2.add_argument('--emg-fee', type=int, default=None)
    p2.add_argument('--emg-step', type=int, default=None)

    a = ap.parse_args()
    if a.cmd == 'init-policy':
        init_policy(a.path, a.random_keys)
        return
    pol = load_policy(a.policy)
    print_report(build_tree(pol, a.funding, a.outdir,
               a.deposit_fee if a.deposit_fee is not None
               else pol.get('deposit_fee', 500),
               a.leaves if a.leaves is not None else pol.get('leaves', 5),
               a.emg_fee if a.emg_fee is not None else pol.get('emg_fee', 500),
               a.emg_step if a.emg_step is not None
               else pol.get('emg_step', 13)))


if __name__ == '__main__':
    main()
