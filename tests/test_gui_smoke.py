# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# tests/test_gui_smoke.py - headless smoke test of the Tk application.
#
# Installs a minimal mock tkinter into sys.modules (machines without a
# display or python3-tk can still verify the GUI constructs and its
# button handlers - Build / Preview / Copy Root - drive the real logic),
# then reloads gui.py and runs VaultApp end to end.
#
# Run: python3 tests/test_gui_smoke.py

import os
import sys
import importlib
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))

import vault_tree as vt
import vault_policy as vp

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    print('%s: %s' % ('ok' if cond else 'FAIL', name))


# ---- a just-functional-enough tkinter mock --------------------------------

CLIPBOARD = []
ERRORS = []

class Var:
    def __init__(self, value=''): self.v = value
    def get(self): return self.v
    def set(self, v): self.v = v

class Widget:
    def __init__(self, master=None, **kw):
        self.master = master
        self.kw = kw
        self._text = ''
    def pack(self, **kw): pass
    def grid(self, **kw): pass
    def config(self, **kw): self.kw.update(kw)
    configure = config
    def insert(self, *a):
        if len(a) == 2 and a[0] == 0:      # Entry.insert(0, text)
            self._text = a[1]
        elif len(a) == 2:                  # Text.insert(index, text)
            self._text += a[1]
    def delete(self, *a): self._text = ''  # Entry(0,'end') / Text('1.0','end')
    def get(self, *a): return self._text
    def clipboard_clear(self): CLIPBOARD.clear()
    def clipboard_append(self, v): CLIPBOARD.append(v)
    def mainloop(self): pass
    def quit(self): pass
    def add_command(self, **kw): pass
    def add_cascade(self, **kw): pass
    def add_separator(self): pass
    def title(self, *a): pass
    def minsize(self, *a): pass

def _noop(*a, **kw): pass

class _MB:
    showerror = staticmethod(lambda *a, **kw: ERRORS.append(a))
    showinfo = staticmethod(lambda *a, **kw: None)

class _FD:
    askopenfilename = staticmethod(lambda *a, **kw: '')
    asksaveasfilename = staticmethod(lambda *a, **kw: '')
    askdirectory = staticmethod(lambda *a, **kw: '')

import types

def install_mock_tk():
    tkmod = types.ModuleType('tkinter')
    tkmod.Tk = Widget
    tkmod.Menu = Widget
    tkmod.StringVar = Var
    ttk = types.ModuleType('tkinter.ttk')
    for name in ('Frame', 'LabelFrame', 'Label', 'Entry', 'Button'):
        setattr(ttk, name, Widget)
    fd = types.ModuleType('tkinter.filedialog'); fd.__dict__['x'] = None
    mb = types.ModuleType('tkinter.messagebox')
    st = types.ModuleType('tkinter.scrolledtext')
    st.ScrolledText = Widget
    for name, mod in (('ttk', ttk), ('filedialog', fd),
                      ('messagebox', mb), ('scrolledtext', st)):
        sys.modules['tkinter.' + name] = mod
        setattr(tkmod, name, mod)
    sys.modules['tkinter'] = tkmod
    fd.askopenfilename = _FD.askopenfilename
    fd.asksaveasfilename = _FD.asksaveasfilename
    fd.askdirectory = _FD.askdirectory
    mb.showerror = _MB.showerror
    mb.showinfo = _MB.showinfo
    return tkmod


# ---- fixtures ---------------------------------------------------------------

FUNDING_VALUE = 100000

def make_funding(path):
    ins = [(b'\xaa' * 32, 0, 0xffffffff)]
    tx = vt.ser_tx(2, ins, [], 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
    blob = vt.build_psbt(tx, [im], 0)
    open(path, 'wb').write(blob)
    return blob

GOOD = {
    'k1': (b'\x02' + bytes(range(1, 33))).hex(),
    'k2': (b'\x03' + bytes(range(33, 65))).hex(),
    'k3': (b'\x02' + bytes(range(65, 97))).hex(),
    'n': '1008', 'f0_max': '10000', 'leaves': '5',
    'emg_fee': '500', 'emg_step': '13', 'deposit_fee': '500',
    'exit_spk': '',
}


# ---- the smoke run ----------------------------------------------------------

saved_modules = {k: v for k, v in sys.modules.items() if 'tkinter' in k}
try:
    install_mock_tk()
    import gui
    importlib.reload(gui)                 # pick up the mock tkinter
    ok('gui sees tkinter (mock)', gui.HAVE_TK)

    app = gui.VaultApp()
    ok('VaultApp constructs', True)

    # every policy field got a widget
    ok('all policy fields have entries',
       set(app.entries) == {k for k, *_ in gui.POLICY_FIELDS})

    # demo policy preloaded
    ok('demo keys preloaded', app.entries['k1'].get() == GOOD['k1'])

    # fund via the paste box (hex), preview, build
    tmp = tempfile.mkdtemp(prefix='gui-smoke-')
    try:
        blob = make_funding(os.path.join(tmp, 'f.psbt'))
        app.paste_txt.insert('1.0', blob.hex())
        app.preview()
        ok('preview shows value',
           str(FUNDING_VALUE) in app.preview_lbl.kw.get('text', '') and
           'PSBT ok' in app.preview_lbl.kw.get('text', ''))
        ok('no error dialogs so far', not ERRORS)

        app.outdir_var.set(os.path.join(tmp, 'out'))
        app.build()
        ok('build succeeds via UI handler', app.report is not None)
        ok('no error dialogs on build', not ERRORS)
        ok('lattice root shown',
           app.report['lattice_root'] in app.root_lbl.kw.get('text', ''))
        ok('manifest written',
           os.path.exists(os.path.join(tmp, 'out', 'manifest.json')))
        ok('result pane has report text',
           app.report['lattice_root'] in app.result_txt.get('1.0', 'end'))

        app.copy_root()
        ok('copy root -> clipboard',
           CLIPBOARD and CLIPBOARD[-1] == app.report['lattice_root'])

        # error path: break a field, rebuild -> error dialog, no crash
        app.entries['n'].delete(0, 'end')
        app.entries['n'].insert(0, '99999')
        app.build()
        ok('bad field -> error dialog', len(ERRORS) == 1 and
           '65535' in ERRORS[0][1])
        ok('previous report preserved on failure', app.report is not None)

        # file-picker route: inject bytes as if a file was chosen
        app.funding_bytes = blob
        app.entries['n'].delete(0, 'end')
        app.entries['n'].insert(0, '1008')
        app.build()
        ok('file route builds too', len(ERRORS) == 1 and
           app.report['lattice_count'] == 5)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

finally:
    for k in list(sys.modules):
        if 'tkinter' in k:
            del sys.modules[k]
    sys.modules.update(saved_modules)

n = sum(1 for _, c in R if c)
print('GUI SMOKE: %d/%d checks pass' % (n, len(R)))
if n != len(R):
    sys.exit(1)
