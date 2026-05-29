#!/usr/bin/env python3
"""minipro-gui — GTK 4 front-end for the minipro programmer tool."""

import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib, Gio, GObject, Pango, Gdk
import subprocess
import threading
import shutil
import os
import re

APP_ID = 'org.minipro.gui'

PROG_TYPES  = ['tl866a', 'tl866ii', 't48', 't56', 't76']
PROG_LABELS = ['TL866A/CS', 'TL866II+', 'T48', 'T56', 'T76']

OPERATIONS = ['Read', 'Write', 'Verify', 'Erase', 'Blank Check', 'Read ID']
PAGES      = ['code', 'data', 'config', 'user', 'calibration']
PAGE_LABELS = ['Default (code)', 'Data', 'Config', 'User', 'Calibration']

NO_FILE_OPS = {'Erase', 'Blank Check', 'Read ID'}
SAVE_OPS    = {'Read'}

_HEX_HDRS_16 = ['0/8', '1/9', '2/A', '3/B', '4/C', '5/D', '6/E', '7/F']

HEX_CSS = b"""
treeview.hex-view {
    font-family: monospace;
    font-size: 9pt;
}
treeview.hex-view row:nth-child(even) {
    background-color: alpha(currentColor, 0.04);
}
treeview.hex-view column header button label {
    font-weight: bold;
}
"""

MAX_HEX_ROWS = 65536   # cap at 1 MB displayed (65536 * 16 bytes)


def find_minipro():
    """Return (binary_path, infoic_path, logicic_path) or (None, None, None)."""
    here = os.path.dirname(os.path.abspath(__file__))

    sys_bin = shutil.which('minipro')
    if sys_bin:
        for share in [
            '/usr/local/share/minipro',
            '/usr/share/minipro',
            os.path.join(os.path.dirname(sys_bin), '..', 'share', 'minipro'),
        ]:
            share = os.path.normpath(share)
            infoic  = os.path.join(share, 'infoic.xml')
            logicic = os.path.join(share, 'logicic.xml')
            if os.path.isfile(infoic) and os.path.isfile(logicic):
                return sys_bin, infoic, logicic

    src_dir = os.path.join(here, 'minipro')
    candidate = os.path.join(src_dir, 'minipro')
    infoic    = os.path.join(src_dir, 'infoic.xml')
    logicic   = os.path.join(src_dir, 'logicic.xml')
    if (os.path.isfile(candidate) and os.access(candidate, os.X_OK)
            and os.path.isfile(infoic) and os.path.isfile(logicic)):
        return candidate, infoic, logicic

    if sys_bin:
        return sys_bin, None, None

    return None, None, None


# ── Hex viewer widget ──────────────────────────────────────────────────────

class HexView(Gtk.Box):
    """XGpro-style hex buffer viewer with 8-bit / 16-bit modes."""

    BYTES_PER_ROW = 16

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''
        self._mode_16bit: bool = False

        # ── controls row ──────────────────────────────────────────────
        ctrl = Gtk.Box(spacing=6,
                       margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)

        ctrl.append(Gtk.Label(label='Buffer select'))
        ctrl.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        self._btn8  = Gtk.ToggleButton(label='8 Bits')
        self._btn16 = Gtk.ToggleButton(label='16 Bits')
        self._btn16.set_group(self._btn8)
        self._btn8.set_active(True)
        self._btn8.connect('toggled', self._on_mode_toggled)
        self._btn16.connect('toggled', self._on_mode_toggled)
        ctrl.append(self._btn8)
        ctrl.append(self._btn16)

        ctrl.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        open_btn = Gtk.Button(label='Open File…')
        open_btn.connect('clicked', self._on_open_file)
        ctrl.append(open_btn)

        self._info_lbl = Gtk.Label(
            label='No data loaded',
            xalign=0, hexpand=True,
            css_classes=['dim-label'],
        )
        ctrl.append(self._info_lbl)

        self.append(ctrl)
        self.append(Gtk.Separator())

        # ── ListStore: addr + 16 data cols + ascii = 18 str columns ───
        self._store = Gtk.ListStore(*([str] * 18))

        self._tv = Gtk.TreeView(model=self._store)
        self._tv.set_headers_visible(True)
        self._tv.set_enable_search(False)
        self._tv.add_css_class('hex-view')

        scroll = Gtk.ScrolledWindow(
            vexpand=True, hexpand=True,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        scroll.set_child(self._tv)
        self.append(scroll)

        self._rebuild_columns()

    # ── column layout ──────────────────────────────────────────────────

    def _rebuild_columns(self):
        for col in list(self._tv.get_columns()):
            self._tv.remove_column(col)

        # Address column — blue, fixed width
        r = Gtk.CellRendererText()
        r.set_property('foreground', '#4499ee')
        col = Gtk.TreeViewColumn('Address', r, text=0)
        col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
        col.set_fixed_width(90)
        self._tv.append_column(col)

        if not self._mode_16bit:
            for i in range(16):
                r = Gtk.CellRendererText()
                r.set_property('xalign', 0.5)
                col = Gtk.TreeViewColumn(f'{i:X}', r, text=i + 1)
                col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                col.set_fixed_width(26)
                self._tv.append_column(col)
        else:
            for i, hdr in enumerate(_HEX_HDRS_16):
                r = Gtk.CellRendererText()
                r.set_property('xalign', 0.5)
                col = Gtk.TreeViewColumn(hdr, r, text=i + 1)
                col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                col.set_fixed_width(40)
                self._tv.append_column(col)

        # ASCII column
        r = Gtk.CellRendererText()
        r.set_property('foreground', '#888888')
        col = Gtk.TreeViewColumn('ASCII', r, text=17)
        self._tv.append_column(col)

    # ── mode toggle ────────────────────────────────────────────────────

    def _on_mode_toggled(self, btn):
        if not btn.get_active():
            return  # only act on the newly-activated button
        self._mode_16bit = (btn is self._btn16)
        self._rebuild_columns()
        self._refresh()

    # ── file loading ───────────────────────────────────────────────────

    def _on_open_file(self, _btn):
        dlg = Gtk.FileDialog(title='Open binary file')
        root = self.get_root()
        if isinstance(root, Gtk.Window):
            dlg.open(root, None, self._open_cb)
        else:
            dlg.open(None, None, self._open_cb)

    def _open_cb(self, dlg, result):
        try:
            f = dlg.open_finish(result)
            self.load_file(f.get_path())
        except Exception:
            pass

    def load_file(self, path: str):
        try:
            with open(path, 'rb') as fh:
                self.load_bytes(fh.read())
        except Exception as exc:
            self._info_lbl.set_text(f'Error loading file: {exc}')

    def load_bytes(self, data: bytes):
        self._data = data
        self._refresh()

    # ── display refresh ────────────────────────────────────────────────

    def _refresh(self):
        self._store.clear()
        data = self._data

        if not data:
            self._info_lbl.set_text('No data loaded')
            return

        truncated = len(data) > MAX_HEX_ROWS * self.BYTES_PER_ROW
        display_data = data[:MAX_HEX_ROWS * self.BYTES_PER_ROW] if truncated else data

        size_str = f'{len(data):,} bytes ({len(data):#010x})'
        if truncated:
            self._info_lbl.set_text(f'{size_str}  —  showing first 1 MB')
        else:
            self._info_lbl.set_text(size_str)

        bpr = self.BYTES_PER_ROW

        for row_start in range(0, len(display_data), bpr):
            chunk = display_data[row_start:row_start + bpr]

            # Address
            if self._mode_16bit:
                word_addr = row_start >> 1
                addr_str = f'{word_addr >> 16:04X}-{word_addr & 0xFFFF:04X}'
            else:
                addr_str = f'{row_start:08X}'

            # 16 data slots (used: 16 in 8-bit, 8 in 16-bit, rest blank)
            cols = [''] * 16
            if not self._mode_16bit:
                for i, b in enumerate(chunk):
                    cols[i] = f'{b:02X}'
            else:
                for i in range(min(8, len(chunk) // 2)):
                    hi = chunk[i * 2]
                    lo = chunk[i * 2 + 1]
                    cols[i] = f'{hi:02X}{lo:02X}'

            # ASCII
            ascii_str = ''.join(
                chr(b) if 0x20 <= b < 0x7F else '.'
                for b in chunk
            ).ljust(bpr)

            self._store.append([addr_str] + cols + [ascii_str])


# ── Device-browser dialog ──────────────────────────────────────────────────

class DeviceBrowserDialog(Gtk.Window):
    __gsignals__ = {
        'device-selected': (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self, parent, device_list):
        super().__init__(
            title='Select Device',
            transient_for=parent,
            modal=True,
            default_width=420,
            default_height=520,
        )
        self._all = device_list

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6,
                      margin_start=8, margin_end=8, margin_top=8, margin_bottom=8)
        self.set_child(box)

        self._search = Gtk.SearchEntry(placeholder_text='Filter…', hexpand=True)
        self._search.connect('search-changed', self._on_search)
        box.append(self._search)

        self._str_model = Gtk.StringList.new(device_list)
        self._str_filter = Gtk.StringFilter.new(
            Gtk.PropertyExpression.new(Gtk.StringObject, None, 'string')
        )
        self._str_filter.set_ignore_case(True)
        self._str_filter.set_match_mode(Gtk.StringFilterMatchMode.SUBSTRING)
        self._filtered = Gtk.FilterListModel.new(self._str_model, self._str_filter)
        self._selection = Gtk.SingleSelection.new(self._filtered)

        factory = Gtk.SignalListItemFactory()
        factory.connect('setup', lambda f, item: item.set_child(
            Gtk.Label(xalign=0, margin_start=4, margin_end=4)))
        factory.connect('bind', lambda f, item:
            item.get_child().set_text(item.get_item().get_string()))

        list_view = Gtk.ListView(model=self._selection, factory=factory,
                                 vexpand=True)
        list_view.connect('activate', self._on_activate)

        scroll = Gtk.ScrolledWindow(
            vexpand=True,
            hscrollbar_policy=Gtk.PolicyType.NEVER,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        scroll.set_child(list_view)
        box.append(scroll)

        self._count_label = Gtk.Label(xalign=0)
        self._update_count()
        box.append(self._count_label)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6,
                          halign=Gtk.Align.END)
        cancel = Gtk.Button(label='Cancel')
        cancel.connect('clicked', lambda _: self.close())
        select = Gtk.Button(label='Select')
        select.add_css_class('suggested-action')
        select.connect('clicked', self._on_select)
        btn_box.append(cancel)
        btn_box.append(select)
        box.append(btn_box)

        self._list_view = list_view

        key = Gtk.EventControllerKey()
        key.connect('key-pressed', self._on_key)
        self.add_controller(key)

    def _on_key(self, ctrl, keyval, keycode, state):
        if keyval == 65307:  # Escape
            self.close()
            return True
        return False

    def _on_search(self, entry):
        self._str_filter.set_search(entry.get_text())
        self._update_count()

    def _update_count(self):
        n = self._filtered.get_n_items()
        total = len(self._all)
        if n == total:
            self._count_label.set_text(f'{total} devices')
        else:
            self._count_label.set_text(f'{n} of {total} devices')

    def _on_activate(self, _lv, pos):
        item = self._filtered.get_item(pos)
        if item:
            self.emit('device-selected', item.get_string())
            self.close()

    def _on_select(self, _btn):
        pos = self._selection.get_selected()
        if pos != 0xFFFFFFFF:
            item = self._filtered.get_item(pos)
            if item:
                self.emit('device-selected', item.get_string())
        self.close()


# ── Main application ───────────────────────────────────────────────────────

class MiniproApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.connect('activate', self._on_activate)
        self.minipro, self.infoic, self.logicic = find_minipro()
        self.device_list: list[str] = []
        self.prog_key  = None
        self._proc     = None
        self._log_end_mark = None
        self._last_op  = None
        self._last_file = None

    # ── build UI ───────────────────────────────────────────────────────

    def _on_activate(self, app):
        self._apply_css()
        self._build_ui()
        self.window.present()
        GLib.idle_add(self._detect_programmer)

    def _apply_css(self):
        provider = Gtk.CssProvider()
        provider.load_from_data(HEX_CSS)
        display = Gdk.Display.get_default()
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _build_ui(self):
        self.window = Gtk.ApplicationWindow(
            application=self,
            title='minipro GUI',
            default_width=860,
            default_height=700,
        )

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window.set_child(root)

        # ── programmer status row ──────────────────────────────────────
        status_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6,
                             margin_start=8, margin_end=8,
                             margin_top=8, margin_bottom=4)

        self._dot = Gtk.Label()
        self._set_dot(False)
        status_bar.append(self._dot)

        self._status_lbl = Gtk.Label(label='Detecting…', xalign=0, hexpand=True)
        status_bar.append(self._status_lbl)

        self._prog_drop = Gtk.DropDown(
            model=Gtk.StringList.new(PROG_LABELS),
            tooltip_text='Manual programmer type for device list',
        )
        self._prog_drop.connect('notify::selected', self._on_prog_drop_changed)
        status_bar.append(self._prog_drop)

        refresh_btn = Gtk.Button(label='⟳ Refresh')
        refresh_btn.connect('clicked', lambda _: self._detect_programmer())
        status_bar.append(refresh_btn)

        root.append(status_bar)
        root.append(Gtk.Separator())

        # ── main form ──────────────────────────────────────────────────
        grid = Gtk.Grid(row_spacing=6, column_spacing=8,
                        margin_start=8, margin_end=8,
                        margin_top=8, margin_bottom=4)
        grid.set_column_homogeneous(False)

        row = 0

        # Device
        grid.attach(self._rlabel('Device:'), 0, row, 1, 1)
        dev_box = Gtk.Box(spacing=4, hexpand=True)
        self._dev_entry = Gtk.Entry(
            placeholder_text='e.g. W25Q64FV@SOP8',
            hexpand=True,
        )
        self._dev_entry.connect('changed', self._update_preview)
        dev_box.append(self._dev_entry)
        browse_dev = Gtk.Button(label='Browse…')
        browse_dev.connect('clicked', self._on_browse_device)
        dev_box.append(browse_dev)
        grid.attach(dev_box, 1, row, 1, 1)
        row += 1

        # Operation
        grid.attach(self._rlabel('Operation:'), 0, row, 1, 1)
        self._op_drop = Gtk.DropDown(
            model=Gtk.StringList.new(OPERATIONS),
            hexpand=True,
        )
        self._op_drop.connect('notify::selected', self._on_op_changed)
        grid.attach(self._op_drop, 1, row, 1, 1)
        row += 1

        # File
        self._file_lbl = self._rlabel('File:')
        grid.attach(self._file_lbl, 0, row, 1, 1)
        self._file_box = Gtk.Box(spacing=4, hexpand=True)
        self._file_entry = Gtk.Entry(
            placeholder_text='Select a file…',
            hexpand=True,
        )
        self._file_entry.connect('changed', self._update_preview)
        self._file_box.append(self._file_entry)
        self._file_btn = Gtk.Button(label='Browse…')
        self._file_btn.connect('clicked', self._on_browse_file)
        self._file_box.append(self._file_btn)
        grid.attach(self._file_box, 1, row, 1, 1)
        row += 1

        # Page + Format on one row
        grid.attach(self._rlabel('Page:'), 0, row, 1, 1)
        row_box = Gtk.Box(spacing=12, hexpand=True)
        self._page_drop = Gtk.DropDown(
            model=Gtk.StringList.new(PAGE_LABELS),
            hexpand=True,
        )
        self._page_drop.connect('notify::selected', self._update_preview)
        row_box.append(self._page_drop)
        row_box.append(self._rlabel('Format:'))
        self._fmt_drop = Gtk.DropDown(
            model=Gtk.StringList.new(['Auto-detect', 'Intel HEX', 'Motorola S-Record']),
            hexpand=True,
        )
        self._fmt_drop.connect('notify::selected', self._update_preview)
        row_box.append(self._fmt_drop)
        grid.attach(row_box, 1, row, 1, 1)
        row += 1

        root.append(grid)

        # ── advanced options ───────────────────────────────────────────
        exp = Gtk.Expander(label='Advanced Options',
                           margin_start=8, margin_end=8, margin_bottom=4)
        opts = Gtk.Grid(row_spacing=4, column_spacing=16,
                        margin_start=16, margin_top=4)

        def chk(label):
            c = Gtk.CheckButton(label=label)
            c.connect('toggled', self._update_preview)
            return c

        self._chk_icsp_vcc   = chk('ICSP + VCC  (-i)')
        self._chk_icsp_novcc = chk('ICSP no VCC  (-I)')
        self._chk_icsp_novcc.set_group(self._chk_icsp_vcc)
        self._chk_skip_erase  = chk('Skip erase  (-e)')
        self._chk_skip_verify = chk('Skip verify  (-v)')
        self._chk_skip_id     = chk('Skip ID check  (-x)')
        self._chk_cont_id     = chk('Continue on ID mismatch  (-y)')
        self._chk_no_sz_err   = chk('Ignore size error  (-s)')
        self._chk_pin_check   = chk('Pin contact check  (-z)')
        self._chk_prot_off    = chk('Disable write protect  (-u)')
        self._chk_prot_on     = chk('Enable write protect  (-P)')

        checks = [
            (self._chk_icsp_vcc,   0, 0), (self._chk_icsp_novcc,  1, 0),
            (self._chk_skip_erase, 0, 1), (self._chk_skip_verify, 1, 1),
            (self._chk_skip_id,    0, 2), (self._chk_cont_id,     1, 2),
            (self._chk_no_sz_err,  0, 3), (self._chk_pin_check,   1, 3),
            (self._chk_prot_off,   0, 4), (self._chk_prot_on,     1, 4),
        ]
        for widget, col, r in checks:
            opts.attach(widget, col, r, 1, 1)
        exp.set_child(opts)
        root.append(exp)

        root.append(Gtk.Separator(margin_top=4))

        # ── command preview + run row ──────────────────────────────────
        action_box = Gtk.Box(spacing=6,
                             margin_start=8, margin_end=8,
                             margin_top=6, margin_bottom=4)

        self._cmd_lbl = Gtk.Label(
            xalign=0, hexpand=True, selectable=True,
            wrap=True, wrap_mode=Pango.WrapMode.CHAR,
            max_width_chars=60,
            css_classes=['dim-label'],
        )
        action_box.append(self._cmd_lbl)

        self._run_btn = Gtk.Button(label='▶  Run', css_classes=['suggested-action'])
        self._run_btn.connect('clicked', self._on_run)
        action_box.append(self._run_btn)

        self._stop_btn = Gtk.Button(label='■  Stop',
                                    css_classes=['destructive-action'],
                                    sensitive=False)
        self._stop_btn.connect('clicked', self._on_stop)
        action_box.append(self._stop_btn)

        root.append(action_box)

        # ── notebook: Hex View + Log ───────────────────────────────────
        self._notebook = Gtk.Notebook(
            vexpand=True,
            margin_start=8, margin_end=8, margin_bottom=8,
        )

        # Tab 0 — Hex View
        self._hex_view = HexView()
        hex_lbl = Gtk.Label(label='Hex View')
        self._notebook.append_page(self._hex_view, hex_lbl)

        # Tab 1 — Log
        log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._scroll = Gtk.ScrolledWindow(
            vexpand=True,
            hscrollbar_policy=Gtk.PolicyType.NEVER,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        self._log_view = Gtk.TextView(
            editable=False, cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
            left_margin=4, right_margin=4, top_margin=4, bottom_margin=4,
        )
        self._log_buf = self._log_view.get_buffer()
        self._log_end_mark = self._log_buf.create_mark(
            'end', self._log_buf.get_end_iter(), False
        )
        self._scroll.set_child(self._log_view)
        log_box.append(self._scroll)
        log_lbl = Gtk.Label(label='Log')
        self._notebook.append_page(log_box, log_lbl)

        root.append(self._notebook)

        self._update_preview()

    def _base_cmd(self):
        cmd = [self.minipro]
        if self.infoic:
            cmd += ['--infoic', self.infoic]
        if self.logicic:
            cmd += ['--logicic', self.logicic]
        return cmd

    @staticmethod
    def _rlabel(text):
        return Gtk.Label(label=text, xalign=1.0)

    # ── programmer detection ───────────────────────────────────────────

    def _detect_programmer(self):
        if not self.minipro:
            here = os.path.dirname(os.path.abspath(__file__))
            self._set_status(False, f'minipro binary not found (looked in PATH and {os.path.join(here, "minipro", "minipro")})')
            return False
        try:
            r = subprocess.run(
                [self.minipro, '-k'],
                capture_output=True, text=True, timeout=15,
            )
            lines = [l.strip() for l in r.stderr.splitlines() if l.strip()]
            line = lines[-1] if lines else ''
            m = re.match(r'^(\w+):\s+(.+)$', line)
            if m:
                key, name = m.group(1), m.group(2)
                self.prog_key = key
                self._set_status(True, name)
                if key in PROG_TYPES:
                    self._prog_drop.set_selected(PROG_TYPES.index(key))
                threading.Thread(target=self._load_devices_and_fw,
                                 args=(key, name), daemon=True).start()
            else:
                self.prog_key = None
                self._set_status(False, line or 'No programmer found')
        except Exception as e:
            self._set_status(False, str(e))
        return False

    def _load_devices_and_fw(self, version, fallback_name):
        if not self.minipro:
            return
        try:
            vr = subprocess.run(
                [self.minipro, '-V'],
                capture_output=True, text=True, timeout=30,
            )
            for ln in vr.stderr.splitlines():
                if ln.startswith('Found '):
                    GLib.idle_add(self._set_status, True, ln[6:])
                    break
        except Exception:
            pass

        try:
            r = subprocess.run(
                self._base_cmd() + ['-q', version, '-l'],
                capture_output=True, text=True, timeout=30,
            )
            names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
            self.device_list = sorted(set(names))
        except Exception:
            pass

    def _load_devices(self):
        version = self.prog_key or PROG_TYPES[self._prog_drop.get_selected()]
        if not version or not self.minipro:
            return
        try:
            r = subprocess.run(
                self._base_cmd() + ['-q', version, '-l'],
                capture_output=True, text=True, timeout=30,
            )
            names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
            self.device_list = sorted(set(names))
        except Exception:
            pass

    def _set_status(self, connected, text):
        self._set_dot(connected)
        self._status_lbl.set_text(text)

    def _set_dot(self, connected):
        color = 'green' if connected else 'red'
        self._dot.set_markup(f'<span color="{color}">●</span>')

    def _on_prog_drop_changed(self, _drop, _param):
        threading.Thread(target=self._load_devices, daemon=True).start()

    # ── device browser ─────────────────────────────────────────────────

    def _on_browse_device(self, _btn):
        if not self.device_list:
            self._log('[Device list not loaded — click Refresh first]\n')
            return
        dlg = DeviceBrowserDialog(self.window, self.device_list)
        dlg.connect('device-selected', lambda _d, name:
                    self._dev_entry.set_text(name))
        dlg.present()

    # ── file browser ───────────────────────────────────────────────────

    def _on_browse_file(self, _btn):
        op = OPERATIONS[self._op_drop.get_selected()]
        dlg = Gtk.FileDialog(title='Save file' if op in SAVE_OPS else 'Open file')
        if op in SAVE_OPS:
            device = self._dev_entry.get_text().strip()
            if device:
                safe = device.replace('@', '_').replace('/', '_')
                dlg.set_initial_name(f'{safe}.bin')
            else:
                dlg.set_initial_name('dump.bin')
            dlg.save(self.window, None, self._file_save_cb)
        else:
            dlg.open(self.window, None, self._file_open_cb)

    def _file_open_cb(self, dlg, result):
        try:
            f = dlg.open_finish(result)
            self._file_entry.set_text(f.get_path())
        except Exception:
            pass

    def _file_save_cb(self, dlg, result):
        try:
            f = dlg.save_finish(result)
            self._file_entry.set_text(f.get_path())
        except Exception:
            pass

    # ── operation change ───────────────────────────────────────────────

    def _on_op_changed(self, _drop, _param):
        op = OPERATIONS[self._op_drop.get_selected()]
        hide = op in NO_FILE_OPS
        self._file_box.set_sensitive(not hide)
        self._file_lbl.set_sensitive(not hide)
        self._update_preview()

    # ── command builder ────────────────────────────────────────────────

    def _build_cmd(self):
        if not self.minipro:
            return None
        cmd = self._base_cmd()

        device = self._dev_entry.get_text().strip()
        if not device:
            return None
        cmd += ['-p', device]

        op = OPERATIONS[self._op_drop.get_selected()]
        filename = self._file_entry.get_text().strip()

        op_flag = {
            'Read': '-r', 'Write': '-w', 'Verify': '-m',
        }
        if op in op_flag:
            if not filename:
                return None
            cmd += [op_flag[op], filename]
        elif op == 'Erase':
            cmd += ['-E']
        elif op == 'Blank Check':
            cmd += ['-b']
        elif op == 'Read ID':
            cmd += ['-D']

        page_idx = self._page_drop.get_selected()
        if page_idx > 0:
            cmd += ['-c', PAGES[page_idx]]

        fmt_idx = self._fmt_drop.get_selected()
        if fmt_idx == 1:
            cmd += ['-f', 'ihex']
        elif fmt_idx == 2:
            cmd += ['-f', 'srec']

        if self._chk_icsp_vcc.get_active():
            cmd += ['-i']
        elif self._chk_icsp_novcc.get_active():
            cmd += ['-I']
        if self._chk_skip_erase.get_active():
            cmd += ['-e']
        if self._chk_skip_verify.get_active():
            cmd += ['-v']
        if self._chk_skip_id.get_active():
            cmd += ['-x']
        if self._chk_cont_id.get_active():
            cmd += ['-y']
        if self._chk_no_sz_err.get_active():
            cmd += ['-s']
        if self._chk_pin_check.get_active():
            cmd += ['-z']
        if self._chk_prot_off.get_active():
            cmd += ['-u']
        if self._chk_prot_on.get_active():
            cmd += ['-P']

        return cmd

    def _update_preview(self, *_):
        cmd = self._build_cmd()
        if not cmd:
            self._cmd_lbl.set_text('')
            return
        display = []
        skip_next = False
        for tok in cmd:
            if skip_next:
                skip_next = False
                continue
            if tok in ('--infoic', '--logicic'):
                skip_next = True
                continue
            display.append(tok)
        self._cmd_lbl.set_text('$ ' + ' '.join(display))

    # ── run / stop ─────────────────────────────────────────────────────

    def _on_run(self, _btn):
        cmd = self._build_cmd()
        if not cmd:
            self._log('[Error: fill in Device and File before running]\n')
            return
        self._last_op   = OPERATIONS[self._op_drop.get_selected()]
        self._last_file = self._file_entry.get_text().strip()
        self._run_btn.set_sensitive(False)
        self._stop_btn.set_sensitive(True)
        self._notebook.set_current_page(1)   # switch to Log tab while running
        self._log(f'\n$ {" ".join(cmd)}\n')
        threading.Thread(target=self._run_cmd, args=(cmd,), daemon=True).start()

    def _on_stop(self, _btn):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _run_cmd(self, cmd):
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in self._proc.stdout:
                GLib.idle_add(self._log, line)
            self._proc.wait()
            rc = self._proc.returncode
            GLib.idle_add(self._log, f'[exit {rc}]\n')
            GLib.idle_add(self._run_finished, rc)
        except Exception as e:
            GLib.idle_add(self._log, f'[error: {e}]\n')
            GLib.idle_add(self._run_finished, -1)
        finally:
            self._proc = None

    def _run_finished(self, rc):
        self._run_btn.set_sensitive(True)
        self._stop_btn.set_sensitive(False)
        if rc == 0 and self._last_op == 'Read' and self._last_file:
            self._hex_view.load_file(self._last_file)
            self._notebook.set_current_page(0)   # switch to Hex View tab

    def _log(self, text):
        end = self._log_buf.get_end_iter()
        self._log_buf.insert(end, text)
        self._log_buf.move_mark(self._log_end_mark, self._log_buf.get_end_iter())
        self._log_view.scroll_mark_onscreen(self._log_end_mark)
        return False


if __name__ == '__main__':
    import sys
    app = MiniproApp()
    sys.exit(app.run(sys.argv))
