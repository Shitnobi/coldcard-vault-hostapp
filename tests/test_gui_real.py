# (c) Copyright 2026 for the vault co-sign policy work; license per COPYING-CC.
#
# tests/test_gui_real.py - REAL-GUI test (actual tkinter + X display).
#
# Constructs the real VaultApp window on a real display and drives it
# the way a user would: types into the paste box, CLICKS the Preview /
# Build / Copy Lattice Root buttons (widget .invoke()), and checks the
# rendered results. Error dialogs are captured (patched) so nothing
# blocks. Gracefully SKIPs when tkinter or a display is unavailable
# (CI / headless machines) - tests/test_gui_smoke.py covers that case
# with a mock.
#
# Run: python3 tests/test_gui_real.py

import os
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))

try:
    import tkinter
    _probe = tkinter.Tk()
    _probe.destroy()
    HAVE_GUI = True
except Exception as e:
    HAVE_GUI = False
    _why = str(e)

if not HAVE_GUI:
    print('GUI REAL: SKIP (no tkinter or no display: %s)' % _why)
    sys.exit(0)

import gui
import vault_tree as vt
import vault_policy as vp

R = []
def ok(name, cond):
    R.append((name, bool(cond)))
    print('%s: %s' % ('ok' if cond else 'FAIL', name))

FUNDING_VALUE = 100000

def make_funding_blob():
    ins = [(b'\xaa' * 32, 0, 0xffffffff)]
    tx = vt.ser_tx(2, ins, [], 0)
    wu = vt.ct_out(vp.p2wsh_spk(b'\x61' * 30), FUNDING_VALUE)
    im = vt.vi(1) + b'\x01' + vt.vi(len(wu)) + wu + b'\x00'
    return vt.build_psbt(tx, [im], 0)


# capture error dialogs instead of blocking on the real display
captured_errors = []
_orig_showerror = gui.messagebox.showerror
gui.messagebox.showerror = lambda *a, **kw: captured_errors.append(a)

app = None
try:
    app = gui.VaultApp()
    app.root.update()
    ok('real window constructs', app.root.winfo_exists())
    ok('title set', app.root.title() == 'Coldcard Vault Host App')

    # real widgets exist and demo policy is preloaded
    ok('policy entries are real Entry widgets',
       all(isinstance(e, gui.ttk.Entry) for e in app.entries.values()))
    ok('demo keys preloaded',
       app.entries['k1'].get() ==
       (b'\x02' + bytes(range(1, 33))).hex())
    ok('cadence prefilled', app.entries['n'].get() == '1008')

    # type a funding PSBT into the paste box (hex) and CLICK Preview
    blob = make_funding_blob()
    app.paste_txt.insert('1.0', blob.hex())
    app.root.update()
    app.preview_btn.invoke()
    app.root.update()
    ok('Preview click parses PSBT',
       'PSBT ok' in app.preview_lbl.cget('text') and
       str(FUNDING_VALUE) in app.preview_lbl.cget('text'))

    # CLICK Build (paste funding route)
    tmp = tempfile.mkdtemp(prefix='gui-real-')
    try:
        app.outdir_var.set(os.path.join(tmp, 'out'))
        app.build_btn.invoke()
        app.root.update()
        ok('Build click succeeds', app.report is not None)
        ok('no error dialogs on build', not captured_errors)
        ok('lattice root rendered in label',
           app.report['lattice_root'] in app.root_lbl.cget('text'))
        ok('report rendered in results pane',
           app.report['lattice_root'] in
           app.result_txt.get('1.0', 'end'))
        ok('manifest written by GUI build',
           os.path.exists(os.path.join(tmp, 'out', 'manifest.json')))

        # CLICK Copy Lattice Root, then read the real clipboard
        app.copy_root_btn.invoke()
        app.root.update()
        ok('Copy Root click -> clipboard',
           app.root.clipboard_get() == app.report['lattice_root'])

        # menus: the File menu entries are wired (smoke-level)
        menubar = app.root.nametowidget(app.root.cget('menu'))
        ok('menu bar has File + Help',
           menubar.index('end') >= 2)

        # error path with a REAL dialog captured (not blocking):
        # break the cadence field and click Build again
        app.entries['n'].delete(0, 'end')
        app.entries['n'].insert(0, '99999')
        app.build_btn.invoke()
        app.root.update()
        ok('bad field -> error dialog raised',
           len(captured_errors) == 1 and '65535' in captured_errors[0][1])
        ok('previous report preserved on failed rebuild',
           app.report is not None)

        # recover and build via the FILE funding route
        app.entries['n'].delete(0, 'end')
        app.entries['n'].insert(0, '1008')
        fn = os.path.join(tmp, 'f.psbt')
        open(fn, 'wb').write(blob)
        # simulate the picker: same state transitions it performs
        app.funding_bytes = blob
        app.fund_file_lbl.config(text=os.path.basename(fn))
        app.build_btn.invoke()
        app.root.update()
        ok('file-route build via click', len(captured_errors) == 1 and
           app.report['lattice_count'] == 5)

        # the mainloop path: schedule a quit and run it for real
        app.root.after(300, app.root.quit)
        app.run()
        ok('mainloop ran and quit cleanly', True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

finally:
    gui.messagebox.showerror = _orig_showerror
    if app is not None and app.root.winfo_exists():
        app.root.destroy()

n = sum(1 for _, c in R if c)
print('GUI REAL: %d/%d checks pass' % (n, len(R)))
if n != len(R):
    sys.exit(1)
