# (c) Copyright 2026. Vault co-signer policy engine (CCC extension).
#
# Pure-python decision core for REV3_PROTOCOL_DRAFT.md (branched P2WSH vault S_v +
# emergency deepvault S_e). No device imports: runs on host (CPython) and target
# (MicroPython) so the exact signing rules can be unit-tested off-device.
#
# Enforces, for the CCC key K3 co-signer slot:
#   P1  emergency shape: 1-in(spk_v)/1-out to spk_e, 0 < F <= f0_max,
#       all nSequence == 0xFFFFFFFD, nLockTime == 0.
#   P2  spend-forbid: never sign a spend of spk_e...
#   P3  ...except the exit ceremony: 1-in(spk_e)/1-out to exit_dest, fee-bounded,
#       K1 partial sig already present in the PSBT.
#   INV-SEQ: vault-ladder spends commit nSequence == N (height-form CSV only);
#       sink entry happens only via the emergency class.
#
# Also includes structural parsers for the S_v / S_e witness scripts
# (INV-BRANCH, INV-KEYLESS: recompute, never trust).

try:
    from uhashlib import sha256 as _sha256
except ImportError:
    from hashlib import sha256 as _sha256

try:
    from ubinascii import unhexlify as _unhex
except ImportError:
    from binascii import unhexlify as _unhex

OP_IF, OP_ELSE, OP_ENDIF = 0x63, 0x67, 0x68
OP_DROP = 0x75
OP_CSV = 0xB2
OP_CMS = 0xAE
OP_CHECKSIGVERIFY = 0xAD

SEQ_EMERGENCY = 0xFFFFFFFD          # CSV disabled, RBF on
SEQ_DISABLE_FLAG = 1 << 31
SEQ_TYPE_TIME = 1 << 22
SEQ_VALUE_MASK = 0xFFFF

MAX_CSV_BLOCKS = 0xFFFF             # 16-bit height-form CSV; ~455 days

# W-04 (validity audit #2): standardness floors, so that "policy-approved"
# implies "broadcastable" under Bitcoin Core's default policy:
#   - DUST_LIMIT: outputs below the dust threshold (546 sats, the
#     25/34-byte scriptPubKey threshold; conservative vs. P2WPKH's 294)
#     are non-standard and will not relay. OP_RETURN outputs are exempt
#     (zero-value data carriers are standard).
#   - _min_relay_fee: fee floor for a 1 sat/vByte default relay policy,
#     computed from a CONSERVATIVE (over-)estimate of the transaction's
#     virtual size: ~96 B base + ~66 vB per segwit vault input (witness
#     ~262 B / 4) + ~43 B per output, rounded up generously.
DUST_LIMIT = 546


def _min_relay_fee(view):
    # minimum fee (sats) for this tx shape to relay at 1 sat/vByte
    return 100 + 70 * len(view["inputs"]) + 45 * len(view["outputs"])


class VaultViolation(Exception):
    pass


def decode_opcode(script, pos):
    # Return (opcode_int, payload, next_pos); payload is bytes or None.
    op = script[pos]
    pos += 1
    if 1 <= op <= 75:
        n = op
        if pos + n > len(script):
            raise VaultViolation("push past end")
        return op, script[pos:pos + n], pos + n
    if op == 0x4c:  # PUSHDATA1
        if pos >= len(script):
            raise VaultViolation("push past end")
        n = script[pos]
        pos += 1
        if pos + n > len(script):
            raise VaultViolation("push past end")
        return op, script[pos:pos + n], pos + n
    return op, None, pos


def decode_pushnum(payload):
    # Script-num decode of a non-negative small-int push.
    if not payload:
        return 0
    n = 0
    for i, c in enumerate(payload):
        n |= c << (8 * i)
    if payload[-1] & 0x80:
        raise VaultViolation("negative pushnum")
    return n


def _expect(script, pos, op):
    if pos >= len(script) or script[pos] != op:
        raise VaultViolation("expect op_%02x" % op)
    return pos + 1


def _expect_pubkey(script, pos):
    op, payload, pos2 = decode_opcode(script, pos)
    if op != 33 or payload is None or payload[0] not in (0x02, 0x03):
        raise VaultViolation("not a compressed pubkey")
    return payload, pos2


def parse_vault_script(wscript):
    # Structural parse of S_v (D-1'):
    #   OP_IF <N> OP_CSV OP_DROP <empty ELSE branch> OP_ENDIF
    #   OP_2 <K1> <K2> <K3> OP_3 OP_CHECKMULTISIG
    # INV-KEYLESS: both branches fall into the shared 2-of-3; the truthy
    # branch ends in CSV DROP, never a keyless OP_1 posture.
    # Returns dict(n=..., keys=[k1, k2, k3]).
    if not wscript or len(wscript) < 111 or len(wscript) > 140:
        raise VaultViolation("S_v size out of range")
    pos = _expect(wscript, 0, OP_IF)
    op, payload, pos = decode_opcode(wscript, pos)
    if payload is None:
        raise VaultViolation("S_v: no N push")
    n = decode_pushnum(payload)
    if not (1 <= n <= MAX_CSV_BLOCKS):
        raise VaultViolation("S_v: N range")
    pos = _expect(wscript, pos, OP_CSV)
    pos = _expect(wscript, pos, OP_DROP)
    pos = _expect(wscript, pos, OP_ELSE)     # empty ELSE branch
    pos = _expect(wscript, pos, OP_ENDIF)
    pos = _expect(wscript, pos, 0x52)        # OP_2
    k1, pos = _expect_pubkey(wscript, pos)
    k2, pos = _expect_pubkey(wscript, pos)
    k3, pos = _expect_pubkey(wscript, pos)
    if k1 == k2 or k1 == k3 or k2 == k3:
        # X-01 (consistency audit #3): OP_CHECKMULTISIG has no pubkey
        # distinctness rule - two signatures from one private key match
        # duplicate pubkeys, so K1==K2 collapses the "2-of-3" to a
        # single party (and the ELSE branch carries no CSV). The device
        # only enrolls the spk hash, so spend-time recognition is the
        # only place this can be caught: fail closed here.
        raise VaultViolation("S_v: duplicate pubkeys collapse the quorum")
    pos = _expect(wscript, pos, 0x53)        # OP_3
    _expect(wscript, pos, OP_CMS)
    return dict(n=n, keys=[k1, k2, k3])


def parse_deepvault_script(wscript):
    # Structural parse of S_e (E-2): <K1> OP_CHECKSIGVERIFY OP_1 <K2> <K3> OP_2 OP_CMS
    # (K1 signs always; then exactly one of K2/K3 -> default-deny even past K1.)
    if not wscript or len(wscript) != 106:
        raise VaultViolation("S_e size")
    k1, pos = _expect_pubkey(wscript, 0)
    pos = _expect(wscript, pos, OP_CHECKSIGVERIFY)
    pos = _expect(wscript, pos, 0x51)        # OP_1
    k2, pos = _expect_pubkey(wscript, pos)
    k3, pos = _expect_pubkey(wscript, pos)
    if k1 == k2 or k1 == k3 or k2 == k3:
        # X-01 (consistency audit #3): K1==K2 makes "K1 AND one of
        # {K2,K3}" a single-party exit. Same fail-closed rule as S_v.
        raise VaultViolation("S_e: duplicate pubkeys collapse the quorum")
    pos = _expect(wscript, pos, 0x52)        # OP_2
    _expect(wscript, pos, OP_CMS)
    return dict(k1=k1, k2=k2, k3=k3)


def p2wsh_spk(wscript):
    return b"\x00\x20" + _sha256(wscript).digest()


def sequence_class(seq):
    # Internal tuple form: ('emergency'|'csv'|'csv_time'|'plain', value)
    if seq == SEQ_EMERGENCY:
        return ("emergency", 0)
    if seq & SEQ_DISABLE_FLAG:
        return ("plain", 0)
    if seq & SEQ_TYPE_TIME:
        return ("csv_time", 0)
    return ("csv", seq & SEQ_VALUE_MASK)


def decode_sequence(seq):
    # Public label form used by tests/UI. Time-form CSV is refused outright
    # (REV3 section 7a: only height-form CSV participates in the protocol).
    if seq == SEQ_EMERGENCY:
        return "emergency"
    if seq & SEQ_DISABLE_FLAG:
        return "disabled"
    if seq & SEQ_TYPE_TIME:
        raise VaultViolation("time-form CSV refused")
    return "csv"


class VaultPolicy:
    # Decision object built from a plain dict (NVS-serializable):
    #   n, sv_hash (hex spk), spk_e (hex), k1_pubkey (hex),
    #   f0_max (sats), exit_spk (hex) -- see testing fixtures.
    def __init__(self, d):
        _h = lambda k: _unhex(d[k]) if d.get(k) else None
        self.spk_v, self.spk_e, self.k1 = _h("sv_hash"), _h("spk_e"), _h("k1_pubkey")
        self.exit_dest = _h("exit_spk")
        self.n = d.get("n", 1008)
        self.f0_max = d.get("f0_max", 10000)

        # Structural sanity, so a mis-enrolled cfg fails at
        # validate/enroll time instead of silently at spend time:
        # - S_v/S_e are P2WSH scriptPubKeys; K1 is a compressed pubkey
        #   (P3's K1 co-signature check can never match otherwise);
        # - the cadence N must be a valid height-form CSV value;
        # - f0_max must be a usable positive fee window.
        # Raise here (=> validate_cfg 'bad policy', could_sign refuse).
        # DESIGN DECISION (issue #6, resolved): exit destinations are
        # confined to P2WSH for now - same shape as sv_hash/spk_e. A
        # non-P2WSH exit_spk is refused at enrollment rather than
        # silently accepted; revisit if arbitrary destinations are
        # ever wanted (the check below is the single gate).
        for nm, spk in (('sv_hash', self.spk_v), ('spk_e', self.spk_e),
                        ('exit_spk', self.exit_dest)):
            if spk is not None and (len(spk) != 34 or spk[:2] != b'\x00\x20'):
                raise VaultViolation('%s must be a P2WSH scriptPubKey' % nm)
        if self.k1 is not None and (len(self.k1) != 33 or
                                    self.k1[0] not in (0x02, 0x03)):
            raise VaultViolation('k1_pubkey must be a 33-byte compressed pubkey')
        if self.n is None or not (1 <= self.n <= MAX_CSV_BLOCKS):
            raise VaultViolation('cadence N must be in 1..%d' % MAX_CSV_BLOCKS)
        if self.f0_max is None or self.f0_max <= 0:
            raise VaultViolation('f0_max must be positive')
        # The exit destination must not be the vault or the sink itself:
        # P3 requires exit ceremonies to pay exit_spk, while INV-SINK
        # forbids non-emergency classes paying spk_e/sv_v - exit_spk ==
        # spk_e (or sv_hash) makes every exit ceremony unsignable, so
        # funds in the sink could never leave (fail-closed fund-lock).
        if self.exit_dest and self.exit_dest in (self.spk_v, self.spk_e):
            raise VaultViolation('exit_spk must differ from sv_hash/spk_e')
        # W-05 (validity audit #2): sv_hash == spk_e makes every S_v
        # emergency input also "spend the sink", so _classify routes
        # emergencies to the exit checker, which can never pass (P3 pays
        # exit_dest, never spk_e) - the emergency path silently self-locks.
        # The exit_spk pair above already had this check; this pair was
        # missed. Refuse at enrollment instead of at spend time.
        if self.spk_v is not None and self.spk_e is not None \
                and self.spk_v == self.spk_e:
            raise VaultViolation('sv_hash must differ from spk_e')

    def _classify(self, view):
        # view = {lock_time:int, inputs:[{spk,value,sequence,part_sigs}], outputs:[...]}
        spends_e = any(i["spk"] == self.spk_e for i in view["inputs"])
        seqs = [i["sequence"] for i in view["inputs"]]
        if all(s == SEQ_EMERGENCY for s in seqs):
            return "exit" if spends_e else "emergency"
        if spends_e:
            # sink spend without emergency discipline is still routed to the
            # exit checker, which default-refuses (P2) unless P3 applies.
            return "exit"
        if any(sequence_class(s)[0] == "csv" for s in seqs):
            return "ladder"
        return "other"

    def check(self, view):
        # Raise VaultViolation to block; return description string otherwise.
        kind = self._classify(view)
        # INV-SINK: entering the deepvault sink is only legal via the
        # emergency class (P1 canonical form). A ladder-shaped tx paying
        # spk_e would smuggle funds deeper without emergency discipline.
        if kind != "emergency" and any(o["spk"] == self.spk_e
                                       for o in view["outputs"]):
            raise VaultViolation("P1: sink entry only via emergency class")
        if kind == "other":
            raise VaultViolation("not a recognized vault class")
        # INV-SIGHASH (V-04 fix): every signature on a vault input - the
        # partials already present AND the one this device is about to add -
        # must commit to SIGHASH_ALL exactly. ANYONECANPAY/NONE/SINGLE
        # signatures are graftable into transactions the policy never saw;
        # upstream consider_dangerous_sighash never blocks ALL|ANYONECANPAY
        # and does not review co-signer-key inputs at all, so the policy
        # owns this invariant itself.
        for i, inp in enumerate(view["inputs"]):
            shs = inp.get("sighashes")
            if shs and any(sh != 1 for sh in shs):
                raise VaultViolation("SIGHASH: vault sigs must be "
                                     "SIGHASH_ALL (input %d)" % i)
            sht = inp.get("sighash_type")
            if sht is not None and sht != 1:
                raise VaultViolation("SIGHASH: input %d declares "
                                     "non-ALL sighash type" % i)
        # All vault classes commit nLockTime == 0 (REV3 5.3). CSV ladder txs
        # especially: locktime set + csv seq is exactly the "bad locktime"
        # shape that would let an attacker back-date pinning.
        if view["lock_time"] != 0:
            raise VaultViolation("vault txs commit nLockTime == 0")
        # W-04 (validity audit #2): dust outputs are non-standard - the
        # device must not co-sign a transaction no node will relay. Applies
        # to every class; OP_RETURN outputs (zero-value data) are exempt.
        for i, o in enumerate(view["outputs"]):
            val = o.get("value")
            if val is None:
                raise VaultViolation("output %d: missing value" % i)
            if val < DUST_LIMIT and bytes(o["spk"])[:1] != b"\x6a":
                raise VaultViolation("output %d: dust (%d sats < %d)"
                                     % (i, val, DUST_LIMIT))
        if kind == "emergency":
            return self._check_emergency(view)
        if kind == "exit":
            return self._check_exit(view)
        return self._check_ladder(view)

    def _check_emergency(self, view):
        # P1: exact sink shape
        if len(view["inputs"]) != 1:
            raise VaultViolation("P1: 1 input")
        if len(view["outputs"]) != 1:
            raise VaultViolation("P1: 1 output")
        out = view["outputs"][0]
        if out["spk"] != self.spk_e or out.get("is_change"):
            raise VaultViolation("P1: dest is the pinned spk_e")
        if view["inputs"][0]["spk"] != self.spk_v:
            raise VaultViolation("P1: must spend the vault")
        self._require_full_utxo(view, "P1")
        for i in view["inputs"]:
            if sequence_class(i["sequence"])[0] != "emergency":
                raise VaultViolation("P1: sequence must be 0xFFFFFFFD")
        fee = view["inputs"][0]["value"] - out["value"]
        if not (0 < fee <= self.f0_max):
            raise VaultViolation("P1: fee out of window")
        self._require_relayable_fee(view, "P1")
        return "emergency F=%d" % fee

    def _require_full_utxo(self, view, tag):
        # V-05 fix: fee-bearing classes (P1/P3) must not evaluate the fee
        # window against attacker-asserted amounts. A witness_utxo-only
        # input (no full prevout tx to txid-cross-check) is refused.
        # Host-test fixtures carry no 'utxo_full' field (their .utxo IS
        # the full utxo) - treated as full, matching view_from_psbt.
        for i, inp in enumerate(view["inputs"]):
            if inp.get("utxo_full") is False:
                raise VaultViolation("%s: full (non-witness) UTXO required "
                                     "on input %d" % (tag, i))

    def _check_ladder(self, view):
        # W-01 (validity audit #2): BIP-68/112 - OP_CHECKSEQUENCEVERIFY
        # cannot execute on a transaction with nVersion < 2 (Bitcoin
        # Core's TransactionSignatureChecker::CheckSequence returns
        # false), so the S_v IF/CSV branch would make the co-signed tx
        # consensus-invalid. Emergency/exit take the ELSE branch (no CSV
        # executes) and stay valid at v1, so the requirement is
        # ladder-specific. Unknown version (host-test view without the
        # fact) fails closed.
        v = view.get("tx_version")
        if v is None or v < 2:
            raise VaultViolation("ladder: nVersion >= 2 required (BIP-68/112)")
        # INV-SEQ: vault spends are cadence-committed; exactly N, height form.
        for i in view["inputs"]:
            if i["spk"] != self.spk_v:
                continue
            cls, n = sequence_class(i["sequence"])
            if cls == "csv_time":
                raise VaultViolation("SEQ: time-form refused")
            if cls != "csv" or n != self.n:
                raise VaultViolation("SEQ: nSequence != N")
        # W-02 (validity audit #2): ladders are signature-bearing - the
        # device's BIP-143 digest embeds the input's nValue, so a
        # witness-utxo-only claim (never txid-cross-checked) would bind
        # the co-signature to an amount the real coin does not have:
        # consensus-invalid on-chain, and the user-facing "spent" amount
        # would be the attacker's claim. Same INV-UTXO rule as P1/P3.
        self._require_full_utxo(view, "P2")
        # W-03 (validity audit #2): fee floor. Zero-fee transactions do
        # not relay (min-relay policy); refuse them like P1/P3 does.
        # NOTE (documented decision): there is deliberately NO ceiling for
        # ladders - after the cadence a 2-of-3 quorum can already withdraw
        # the full amount anywhere, so a fee cap adds no security; the
        # P1/P3 windows exist to bound the no-timelock paths.
        self._require_relayable_fee(view, "P2")
        spent = sum(i["value"] for i in view["inputs"] if i["spk"] == self.spk_v)
        if any(o["spk"] == self.spk_v for o in view["outputs"]):
            return "ladder: state transition (%d sats spent)" % spent
        return "ladder: withdrawal (%d sats spent)" % spent

    def _require_relayable_fee(self, view, tag):
        # W-04/W-03 (validity audit #2): the fee must meet a min-relay
        # floor (1 sat/vByte against a conservative vsize estimate) so a
        # policy-approved transaction is actually broadcastable. Fail
        # closed when values are missing (cannot compute).
        try:
            fee = (sum(i["value"] for i in view["inputs"]) -
                   sum(o["value"] for o in view["outputs"]))
        except Exception:
            raise VaultViolation("%s: cannot compute fee" % tag)
        if fee is None:
            raise VaultViolation("%s: cannot compute fee" % tag)
        floor = _min_relay_fee(view)
        if fee < floor:
            raise VaultViolation("%s: fee %d below min-relay floor %d"
                                 % (tag, fee, floor))

    def _check_exit(self, view):
        # P2 (spend-forbid) is enforced structurally: _classify routes
        # every spk_e-spending tx here, and only the exact P3 shape
        # below survives; anything else is refused.
        if len(view["inputs"]) != 1 or len(view["outputs"]) != 1:
            raise VaultViolation("P3: ceremonies are 1-in/1-out")
        if view["outputs"][0]["spk"] != self.exit_dest:
            raise VaultViolation("P3: must re-enroll to fresh spk_v'")
        self._require_full_utxo(view, "P3")
        fee = view["inputs"][0]["value"] - view["outputs"][0]["value"]
        if not (0 < fee <= self.f0_max):
            raise VaultViolation("P3: fee out of window")
        self._require_relayable_fee(view, "P3")
        # belt-and-braces behind the E-2 script: K1's sig must already be present
        # (validity of that signature - DER shape, low-S, SIGHASH_ALL and
        # the ECDSA check against the BIP-143 digest - is enforced by
        # vault.could_sign via vault_signing.verify_input_sigs: V-03 fix)
        if not any(self.k1 in (i.get("part_sigs") or []) for i in view["inputs"]):
            raise VaultViolation("P3: K1 co-signature required")
        return "exit ceremony F=%d" % fee


# ---- Enrollment-time lattice commitment --------------------------------
# Per docs/vault_lattice_commitment_plan.md (T3/T4). NOT a spend-time
# enforcement mechanism: the device proves, at enrollment, that it agrees
# with the host on the exact committed PSBT batch; runtime enforcement
# remains the shape rules above.

MAX_LATTICE_LEAVES = 0x10000        # T4: 2^16 leaf cap


def sha256d(b):
    # Bitcoin-convention double SHA256.
    return _sha256(_sha256(b).digest()).digest()


def _le32(i):
    return bytes((i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff, (i >> 24) & 0xff))


def leaf_hash(index, unsigned_tx_bytes):
    # T3: leaf_i = dSHA256(LE32(i) || unsigned_tx_bytes_i).
    # - unsigned tx = PSBT global transaction: excludes all partial sigs
    #   (sigs may legitimately vary/assemble later), so txid-equal txs
    #   hash equal regardless of PSBT key-ordering across producers.
    # - LE32 index prefix is position-binding: kills reorder ambiguity.
    if not (0 <= index < MAX_LATTICE_LEAVES):
        raise VaultViolation("leaf index out of range: %d" % index)
    return sha256d(_le32(index) + bytes(unsigned_tx_bytes))


def lattice_root(leaf_iter):
    # T4: Bitcoin-style dup-last Merkle root over a LEAF STREAM.
    # Carry-stack: stack[h] holds at most one unpaired node at height h,
    # so peak RAM is O(log n) - a few KB on Mk4/Q even at the 2^16 cap.
    # A pending node at a lower height always covers LATER leaves, so the
    # final reduce walks the pendings right-to-left (low h to high h);
    # the rightmost pending promotes by self-duplication (dup-last).
    # Returns (root_bytes32, count). Empty set refused; cap enforced.
    stack = []
    count = 0
    for leaf in leaf_iter:
        leaf = bytes(leaf)
        if len(leaf) != 32:
            raise VaultViolation("leaf must be 32 bytes")
        count += 1
        if count > MAX_LATTICE_LEAVES:
            raise VaultViolation("lattice too large (> %d)" % MAX_LATTICE_LEAVES)
        node = leaf
        h = 0
        while h < len(stack) and stack[h] is not None:
            node = sha256d(stack[h] + node)
            stack[h] = None
            h += 1
        if h == len(stack):
            stack.append(node)
        else:
            stack[h] = node

    if count == 0:
        raise VaultViolation("empty lattice")

    acc, ha = None, 0
    for h in range(len(stack)):
        node = stack[h]
        if node is None:
            continue
        if acc is None:
            acc, ha = node, h
            continue
        while ha < h:
            acc = sha256d(acc + acc)        # dup-promote the right subtree
            ha += 1
        acc = sha256d(node + acc)
        ha = h + 1
    return acc, count
