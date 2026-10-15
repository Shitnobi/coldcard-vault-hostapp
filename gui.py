#!/usr/bin/env python3
# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# gui.py - graphical front end for the vault host application.
#
# Wraps vault_tree.py (same rule layer, same build path as the CLI):
#   - Policy section: create / load / save the policy JSON, edit every
#     field (co-sign keys K1/K2/K3, cadence N, fee window, lattice size
#     and fees, optional exit destination)
#   - Funding section: accept a funding PSBT from a FILE (picker) or by
#     PASTING hex / base64 text, with an input/output/value preview
#   - Build: runs the full vault tree build and renders the report -
#     deposit txid, vault value, leaf files and the LATTICE ROOT the
#     user must compare against the Coldcard's screen at enrollment
#
# Run:  python3 gui.py
# (tkinter is in the Python standard library; on Debian/Ubuntu:
#  sudo apt install python3-tk)
#
# All non-Tk logic lives in plain functions below (decode_psbt_text,
# policy_from_fields, preview_psbt, format_report) so it is testable
# headlessly - see tests/test_gui_logic.py. tkinter is imported lazily.

import os
import sys
import json
import base64
import secrets
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import vault_tree as vt
import vault_policy as vp

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    HAVE_TK = True
except ImportError:
    HAVE_TK = False

APP_TITLE = 'Coldcard Vault Host App'
POLICY_FIELDS = [
    # (key, label, default, validator)
    ('k1', 'K1 pubkey (hex)', None, 'pubkey'),
    ('k2', 'K2 pubkey (hex)', None, 'pubkey'),
    ('k3', 'K3 pubkey (hex)', None, 'pubkey'),
    ('n', 'Cadence N (blocks)', '1008', 'int:1:65535'),
    ('f0_max', 'Max fee F0 (sats)', '10000', 'int:1:'),
    ('leaves', 'Lattice leaves', '5', 'int:1:'),
    ('emg_fee', 'Emergency fee (sats)', '500', 'int:1:'),
    ('emg_step', 'Fee step (sats)', '13', 'int:0:'),
    ('deposit_fee', 'Deposit fee (sats)', '500', 'int:1:'),
    ('exit_spk', 'Exit spk (hex, optional)', '', 'spk'),
]

DEFAULT_KEYS = {
    # the fixed demo keys from 'init-policy' (protocol-shape testing
    # only, NOT for real funds)
    'k1': b'\x02' + bytes(range(1, 33)),
    'k2': b'\x03' + bytes(range(33, 65)),
    'k3': b'\x02' + bytes(range(65, 97)),
}


def default_policy(random_keys=False):
    # a complete, valid starter policy (same sample 'init-policy'
    # writes). random_keys=True swaps in fresh random demo keys.
    keys = ((random_pubkey(), random_pubkey(), random_pubkey())
            if random_keys else
            (DEFAULT_KEYS['k1'], DEFAULT_KEYS['k2'], DEFAULT_KEYS['k3']))
    return {
        'k1': keys[0], 'k2': keys[1], 'k3': keys[2],
        'n': 1008, 'f0_max': 10000, 'leaves': 5,
        'emg_fee': 500, 'emg_step': 13, 'deposit_fee': 500,
        'exit_spk': '',
    }


# ---- headless-testable logic ----------------------------------------------

def decode_psbt_text(text):
    # Funding PSBT pasted as text: hex ('70736274ff...') or base64
    # ('cHNidP8...'). Whitespace-insensitive. Raises vt.HostappError.
    t = ''.join((text or '').split())
    if not t:
        raise vt.HostappError('no PSBT text was pasted')
    for decoder in (bytes.fromhex,
                    lambda s: base64.b64decode(s, validate=True)):
        try:
            b = decoder(t)
        except Exception:
            continue
        if b[:5] == b'psbt\xff':
            return b
    raise vt.HostappError(
        'not a PSBT: expected hex or base64 text decoding to a blob '
        "starting with the PSBT magic ('psbt' + 0xff)")


def random_pubkey():
    return bytes([0x02 if secrets.randbelow(2) else 0x03]) + \
        secrets.token_bytes(32)


def _parse_int(name, s, lo, hi):
    try:
        v = int(s.strip())
    except (ValueError, AttributeError):
        raise vt.HostappError('%s: not a number (%r)' % (name, s))
    if lo is not None and v < lo:
        raise vt.HostappError('%s: must be >= %d (got %d)' % (name, lo, v))
    if hi is not None and v > hi:
        raise vt.HostappError('%s: must be <= %d (got %d)' % (name, hi, v))
    return v


def _parse_pubkey(name, s):
    try:
        b = bytes.fromhex((s or '').strip())
    except ValueError:
        raise vt.HostappError('%s: not valid hex' % name)
    if len(b) != 33 or b[0] not in (0x02, 0x03):
        raise vt.HostappError(
            '%s: must be a 33-byte compressed pubkey (02/33 + 32 bytes)'
            % name)
    return b


def policy_from_fields(fields):
    # fields: {key: string} straight from the GUI entries (or a test).
    # Returns the pol dict consumed by vt.build_tree; raises
    # vt.HostappError with a human-readable message on any bad field.
    pol = {}
    for key, label, _default, kind in POLICY_FIELDS:
        s = fields.get(key, '')
        if kind == 'pubkey':
            pol[key] = _parse_pubkey(label, s)
        elif kind == 'spk':
            s = (s or '').strip()
            if s:
                try:
                    b = bytes.fromhex(s)
                except ValueError:
                    raise vt.HostappError('%s: not valid hex' % label)
                if len(b) != 34 or b[:2] != b'\x00\x20':
                    raise vt.HostappError(
                        '%s: must be a P2WSH scriptPubKey (34 bytes: '
                        'OP_0 PUSH32 <hash>)' % label)
                pol[key] = s
        else:
            _kind, lo, hi = kind.split(':')
            lo = int(lo) if lo else None
            hi = int(hi) if hi else None
            pol[key] = _parse_int(label, s, lo, hi)
    # cross-field sanity, mirroring the device-side policy checks
    if pol['emg_fee'] + (pol['leaves'] - 1) * pol['emg_step'] > \
            pol['f0_max']:
        raise vt.HostappError(
            'highest emergency leaf fee (%d) exceeds Max fee F0 (%d)'
            % (pol['emg_fee'] + (pol['leaves'] - 1) * pol['emg_step'],
               pol['f0_max']))
    # structural validation via the real rule layer (script shapes,
    # N encoding): fails here rather than mid-build
    vt.build_scripts(pol)
    return pol


def fields_from_policy(pol):
    # pol dict (bytes keys / ints) -> {key: display string} for the GUI
    out = {}
    for key, _label, _default, _kind in POLICY_FIELDS:
        v = pol.get(key, '')
        if isinstance(v, bytes):
            v = v.hex()
        out[key] = str(v)
    return out


def policy_to_json(pol):
    return json.dumps(
        {k: (v.hex() if isinstance(v, bytes) else v)
         for k, v in pol.items()}, indent=1)


def policy_from_json(text):
    # inverse of policy_to_json; raises vt.HostappError on bad JSON
    try:
        d = json.loads(text)
        if not isinstance(d, dict):
            raise ValueError('not an object')
    except Exception as e:
        raise vt.HostappError('not a valid policy file: %s' % e)
    for k in ('k1', 'k2', 'k3'):
        if k in d:
            try:
                d[k] = bytes.fromhex(d[k])
            except (ValueError, TypeError):
                raise vt.HostappError('%s: not valid hex' % k)
    return d


def preview_psbt(blob):
    # Lightweight summary of a funding PSBT for the preview pane.
    # Raises vt.HostappError (via the parser) on malformed input.
    try:
        ps = vt.parse_psbt(blob)
    except (AssertionError, ValueError, IndexError, struct.error) as e:
        raise vt.HostappError('not a parseable PSBT: %s' % e)
    total = sum(v for _, v in ps['wutxos'])
    return {
        'inputs': len(ps['ins']),
        'outputs': len(ps['outs']),
        'value': total,
        'has_witness_utxos': bool(ps['wutxos']),
    }


def format_report(rep):
    # build_tree() report -> the text shown in the results pane
    lines = []
    if rep['warnings']:
        for w in rep['warnings']:
            lines.append('WARNING: %s' % w)
        lines.append('')
    lines.append('Funding mode:      %s' % rep['funding_mode'])
    lines.append('Funding value:     %d sats' % rep['funding_value'])
    lines.append('Vault value:       %d sats (deposit fee %d)' %
                 (rep['vault_value'], rep['deposit_fee']))
    lines.append('Vault vout:        %d' % rep['vault_vout'])
    lines.append('Deposit txid:      %s' % rep['deposit_txid'])
    lines.append('Vault address spk: %s' % rep['spk_v'])
    lines.append('Lattice:           %d emergency leaves, fees %d..%d sats'
                 % (rep['lattice_count'], rep['emg_fee'],
                    rep['emg_fee'] + (len(rep['leaf_files']) - 1) *
                    rep['emg_step']))
    lines.append('Leaf files:        %s (enroll on the Coldcard in this '
                 'order)' % ', '.join(rep['leaf_files']))
    lines.append('')
    lines.append('LATTICE ROOT (compare with the Coldcard screen):')
    lines.append(rep['lattice_root'])
    lines.append('')
    lines.append('Output: %s' % rep['outdir'])
    return '\n'.join(lines)


def run_build(pol, funding, outdir):
    # the exact call the Build button makes (and what the headless
    # tests exercise): full vault tree build from a policy dict and
    # funding PSBT bytes (or a file path)
    return vt.build_tree(pol, funding, outdir,
                         pol['deposit_fee'], pol['leaves'],
                         pol['emg_fee'], pol['emg_step'])


# ---- the Tk application ----------------------------------------------------

class VaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.minsize(760, 640)
        self.funding_bytes = None       # from the file picker
        self.report = None
        self._build_ui()

    # -- UI construction -----------------------------------------------------

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        mfile = tk.Menu(menubar, tearoff=0)
        mfile.add_command(label='New Policy (demo keys)',
                          command=self.new_policy_demo)
        mfile.add_command(label='New Policy (random keys)',
                          command=self.new_policy_random)
        mfile.add_command(label='Load Policy...', command=self.load_policy)
        mfile.add_command(label='Save Policy As...',
                          command=self.save_policy)
        mfile.add_separator()
        mfile.add_command(label='Exit', command=self.root.quit)
        menubar.add_cascade(label='File', menu=mfile)
        mhelp = tk.Menu(menubar, tearoff=0)
        mhelp.add_command(label='About', command=self.about)
        menubar.add_cascade(label='Help', menu=mhelp)
        self.root.config(menu=menubar)

        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill='both', expand=True)

        # --- policy ---
        pol = ttk.LabelFrame(outer, text='Vault Policy', padding=8)
        pol.pack(fill='x')
        self.entries = {}
        for row, (key, label, default, _kind) in enumerate(POLICY_FIELDS):
            ttk.Label(pol, text=label + ':').grid(
                row=row // 2, column=(row % 2) * 2, sticky='e',
                padx=(0, 4), pady=2)
            e = ttk.Entry(pol, width=44 if kind_is_long(key) else 14)
            e.insert(0, default if default else '')
            e.grid(row=row // 2, column=(row % 2) * 2 + 1,
                   sticky='w', pady=2)
            self.entries[key] = e
        btns = ttk.Frame(pol)
        btns.grid(row=5, column=0, columnspan=4, sticky='w', pady=(6, 0))
        ttk.Button(btns, text='New (demo keys)',
                   command=self.new_policy_demo).pack(side='left')
        ttk.Button(btns, text='New (random keys)',
                   command=self.new_policy_random).pack(side='left', padx=4)
        ttk.Button(btns, text='Load...',
                   command=self.load_policy).pack(side='left')
        ttk.Button(btns, text='Save As...',
                   command=self.save_policy).pack(side='left', padx=4)

        # --- funding ---
        fund = ttk.LabelFrame(
            outer, text='Funding PSBT (choose a file or paste hex/base64)',
            padding=8)
        fund.pack(fill='x', pady=(10, 0))
        row1 = ttk.Frame(fund)
        row1.pack(fill='x')
        ttk.Button(row1, text='Choose PSBT file...',
                   command=self.pick_funding_file).pack(side='left')
        self.fund_file_lbl = ttk.Label(
            row1, text='no file chosen', foreground='#666')
        self.fund_file_lbl.pack(side='left', padx=8)
        ttk.Label(fund, text='...or paste PSBT (hex or base64):').pack(
            anchor='w', pady=(6, 2))
        self.paste_txt = scrolledtext.ScrolledText(fund, height=4,
                                                   wrap='char')
        self.paste_txt.pack(fill='x')
        self.preview_lbl = ttk.Label(
            fund, text='', foreground='#050')
        self.preview_lbl.pack(anchor='w', pady=(4, 0))
        ttk.Button(fund, text='Preview PSBT',
                   command=self.preview).pack(anchor='w', pady=(4, 0))

        # --- output + build ---
        outrow = ttk.Frame(outer)
        outrow.pack(fill='x', pady=(10, 0))
        ttk.Label(outrow, text='Output directory:').pack(side='left')
        self.outdir_var = tk.StringVar(
            value=os.path.join(os.getcwd(), 'vault-out'))
        ttk.Entry(outrow, textvariable=self.outdir_var).pack(
            side='left', fill='x', expand=True, padx=4)
        ttk.Button(outrow, text='Browse...',
                   command=self.pick_outdir).pack(side='left')
        self.build_btn = ttk.Button(outer, text='Build Vault Tree',
                                    command=self.build)
        self.build_btn.pack(fill='x', pady=(10, 0))

        # --- results ---
        res = ttk.LabelFrame(outer, text='Results', padding=8)
        res.pack(fill='both', expand=True, pady=(10, 0))
        self.root_lbl = ttk.Label(res, text='lattice root: (not built yet)',
                                  wraplength=640, font=('Courier', 10))
        self.root_lbl.pack(anchor='w')
        ttk.Button(res, text='Copy Lattice Root',
                   command=self.copy_root).pack(anchor='w', pady=(4, 6))
        self.result_txt = scrolledtext.ScrolledText(res, height=10,
                                                    state='disabled',
                                                    font=('Courier', 9))
        self.result_txt.pack(fill='both', expand=True)

        self.new_policy_demo()

    # -- actions ---------------------------------------------------------------

    def _fields(self):
        return {k: e.get() for k, e in self.entries.items()}

    def _set_fields(self, pol):
        for key, val in fields_from_policy(pol).items():
            self.entries[key].delete(0, 'end')
            self.entries[key].insert(0, val)

    def new_policy_demo(self):
        self._set_fields(default_policy(random_keys=False))

    def new_policy_random(self):
        self._set_fields(default_policy(random_keys=True))

    def load_policy(self):
        fn = filedialog.askopenfilename(
            title='Load vault policy', filetypes=[('Policy JSON', '*.json'),
                                                  ('All files', '*.*')])
        if not fn:
            return
        try:
            pol = policy_from_json(open(fn).read())
            # validate everything the build will need, right now
            policy_from_fields(fields_from_policy(pol))
        except vt.HostappError as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        self._set_fields(pol)

    def save_policy(self):
        try:
            pol = policy_from_fields(self._fields())
        except vt.HostappError as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        fn = filedialog.asksaveasfilename(
            title='Save vault policy', defaultextension='.json',
            filetypes=[('Policy JSON', '*.json')])
        if not fn:
            return
        open(fn, 'w').write(policy_to_json(pol))
        messagebox.showinfo(APP_TITLE, 'Policy saved to %s' % fn)

    def pick_funding_file(self):
        fn = filedialog.askopenfilename(
            title='Choose funding PSBT',
            filetypes=[('PSBT', '*.psbt'), ('All files', '*.*')])
        if not fn:
            return
        try:
            blob = open(fn, 'rb').read()
            if blob[:5] != b'psbt\xff':
                raise vt.HostappError('file does not start with the PSBT '
                                      'magic')
            self.funding_bytes = blob
            self.fund_file_lbl.config(text=os.path.basename(fn),
                                      foreground='#050')
            self._show_preview(blob)
        except (OSError, vt.HostappError) as e:
            self.funding_bytes = None
            self.fund_file_lbl.config(text='no file chosen',
                                      foreground='#666')
            messagebox.showerror(APP_TITLE, str(e))

    def _funding(self):
        # funding PSBT bytes from the file picker, else the paste box
        if self.funding_bytes is not None:
            return self.funding_bytes
        return decode_psbt_text(self.paste_txt.get('1.0', 'end'))

    def _show_preview(self, blob):
        p = preview_psbt(blob)
        self.preview_lbl.config(
            text='PSBT ok: %d input(s), %d output(s), funding value %d sats'
                 % (p['inputs'], p['outputs'], p['value']))

    def preview(self):
        try:
            blob = self._funding()
            self._show_preview(blob)
        except vt.HostappError as e:
            self.preview_lbl.config(text='PSBT error: %s' % e,
                                    foreground='#a00')
        except (AssertionError, ValueError, IndexError) as e:
            self.preview_lbl.config(text='PSBT error: %s' % e,
                                    foreground='#a00')

    def pick_outdir(self):
        d = filedialog.askdirectory(title='Choose output directory')
        if d:
            self.outdir_var.set(d)

    def build(self):
        try:
            pol = policy_from_fields(self._fields())
            funding = self._funding()
            rep = run_build(pol, funding, self.outdir_var.get().strip())
        except vt.HostappError as e:
            messagebox.showerror(APP_TITLE, str(e))
            return
        except (AssertionError, ValueError, IndexError, OSError) as e:
            messagebox.showerror(APP_TITLE, 'build failed: %s' % e)
            return
        self.report = rep
        self.root_lbl.config(text='lattice root: %s' % rep['lattice_root'],
                             foreground='#050')
        self.result_txt.config(state='normal')
        self.result_txt.delete('1.0', 'end')
        self.result_txt.insert('1.0', format_report(rep))
        self.result_txt.config(state='disabled')

    def copy_root(self):
        if not self.report:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.report['lattice_root'])

    def about(self):
        messagebox.showinfo(
            'About', APP_TITLE + '\n\n'
            'Host side of the Coldcard vault co-signing protocol.\n'
            'Builds the deposit + emergency-exit lattice from a funding\n'
            'PSBT; enroll the manifest and leaf PSBTs on the Coldcard\n'
            'and verify the displayed lattice root matches.\n\n'
            'CLI equivalent: python3 vault_tree.py build ...')

    def run(self):
        self.root.mainloop()


def kind_is_long(key):
    return key in ('k1', 'k2', 'k3', 'exit_spk')


def main():
    if not HAVE_TK:
        print('tkinter is not available in this Python installation.\n'
              'On Debian/Ubuntu:  sudo apt install python3-tk\n'
              '(the CLI in vault_tree.py works without it)')
        sys.exit(1)
    VaultApp().run()


if __name__ == '__main__':
    main()
