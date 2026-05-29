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
import zlib
import json
import math

APP_ID = 'org.minipro.gui'

PROG_TYPES  = ['tl866a', 'tl866ii', 't48', 't56', 't76']
PROG_LABELS = ['TL866A/CS', 'TL866II+', 'T48', 'T56', 'T76']

OPERATIONS = ['Read', 'Write', 'Verify', 'Erase', 'Blank Check', 'Read ID']
PAGES      = ['code', 'data', 'config', 'user', 'calibration']
PAGE_LABELS = ['Default (code)', 'Data', 'Config', 'User', 'Calibration']

NO_FILE_OPS = {'Erase', 'Blank Check', 'Read ID'}
SAVE_OPS    = {'Read'}

_HEX_HDRS_16 = ['0/8', '1/9', '2/A', '3/B', '4/C', '5/D', '6/E', '7/F']

# Matches minipro progress lines: "Reading Code...  47%"
_PROGRESS_RE = re.compile(r'(Reading|Writing|Verifying|Erasing)\s+\S+\.\.\.\s+(\d+)%')

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

MAX_HEX_ROWS = 65536   # cap at 1 MB displayed

_CONFIG_PATH = os.path.join(
    GLib.get_user_config_dir(), 'minipro-gui', 'config.json'
)


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


# ── Entropy helpers ────────────────────────────────────────────────────────

def _block_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h

def _entropy_color(e: float):
    """Return (r, g, b) for an entropy value 0–8."""
    t = e / 8.0
    if t < 0.25:                    # blank / very low
        return (0.2, 0.35, 0.9)
    elif t < 0.65:                  # code / data
        return (0.2 + t, 0.85 - t * 0.3, 0.2)
    else:                           # compressed / encrypted
        return (0.9, 0.85 - t * 0.7, 0.1)


# ── 6502 / 65C02 disassembler ──────────────────────────────────────────────

# (mnemonic, addressing_mode, byte_length)
_6502_OPS: dict[int, tuple[str, str, int]] = {
    0x00:('BRK','imp',1), 0x01:('ORA','idx',2), 0x05:('ORA','zpg',2),
    0x06:('ASL','zpg',2), 0x08:('PHP','imp',1), 0x09:('ORA','imm',2),
    0x0A:('ASL','acc',1), 0x0D:('ORA','abs',3), 0x0E:('ASL','abs',3),
    0x10:('BPL','rel',2), 0x11:('ORA','idy',2), 0x15:('ORA','zpx',2),
    0x16:('ASL','zpx',2), 0x18:('CLC','imp',1), 0x19:('ORA','aby',3),
    0x1D:('ORA','abx',3), 0x1E:('ASL','abx',3), 0x20:('JSR','abs',3),
    0x21:('AND','idx',2), 0x24:('BIT','zpg',2), 0x25:('AND','zpg',2),
    0x26:('ROL','zpg',2), 0x28:('PLP','imp',1), 0x29:('AND','imm',2),
    0x2A:('ROL','acc',1), 0x2C:('BIT','abs',3), 0x2D:('AND','abs',3),
    0x2E:('ROL','abs',3), 0x30:('BMI','rel',2), 0x31:('AND','idy',2),
    0x35:('AND','zpx',2), 0x36:('ROL','zpx',2), 0x38:('SEC','imp',1),
    0x39:('AND','aby',3), 0x3D:('AND','abx',3), 0x3E:('ROL','abx',3),
    0x40:('RTI','imp',1), 0x41:('EOR','idx',2), 0x45:('EOR','zpg',2),
    0x46:('LSR','zpg',2), 0x48:('PHA','imp',1), 0x49:('EOR','imm',2),
    0x4A:('LSR','acc',1), 0x4C:('JMP','abs',3), 0x4D:('EOR','abs',3),
    0x4E:('LSR','abs',3), 0x50:('BVC','rel',2), 0x51:('EOR','idy',2),
    0x55:('EOR','zpx',2), 0x56:('LSR','zpx',2), 0x58:('CLI','imp',1),
    0x59:('EOR','aby',3), 0x5D:('EOR','abx',3), 0x5E:('LSR','abx',3),
    0x60:('RTS','imp',1), 0x61:('ADC','idx',2), 0x65:('ADC','zpg',2),
    0x66:('ROR','zpg',2), 0x68:('PLA','imp',1), 0x69:('ADC','imm',2),
    0x6A:('ROR','acc',1), 0x6C:('JMP','ind',3), 0x6D:('ADC','abs',3),
    0x6E:('ROR','abs',3), 0x70:('BVS','rel',2), 0x71:('ADC','idy',2),
    0x75:('ADC','zpx',2), 0x76:('ROR','zpx',2), 0x78:('SEI','imp',1),
    0x79:('ADC','aby',3), 0x7D:('ADC','abx',3), 0x7E:('ROR','abx',3),
    0x81:('STA','idx',2), 0x84:('STY','zpg',2), 0x85:('STA','zpg',2),
    0x86:('STX','zpg',2), 0x88:('DEY','imp',1), 0x8A:('TXA','imp',1),
    0x8C:('STY','abs',3), 0x8D:('STA','abs',3), 0x8E:('STX','abs',3),
    0x90:('BCC','rel',2), 0x91:('STA','idy',2), 0x94:('STY','zpx',2),
    0x95:('STA','zpx',2), 0x96:('STX','zpy',2), 0x98:('TYA','imp',1),
    0x99:('STA','aby',3), 0x9A:('TXS','imp',1), 0x9D:('STA','abx',3),
    0xA0:('LDY','imm',2), 0xA1:('LDA','idx',2), 0xA2:('LDX','imm',2),
    0xA4:('LDY','zpg',2), 0xA5:('LDA','zpg',2), 0xA6:('LDX','zpg',2),
    0xA8:('TAY','imp',1), 0xA9:('LDA','imm',2), 0xAA:('TAX','imp',1),
    0xAC:('LDY','abs',3), 0xAD:('LDA','abs',3), 0xAE:('LDX','abs',3),
    0xB0:('BCS','rel',2), 0xB1:('LDA','idy',2), 0xB4:('LDY','zpx',2),
    0xB5:('LDA','zpx',2), 0xB6:('LDX','zpy',2), 0xB8:('CLV','imp',1),
    0xB9:('LDA','aby',3), 0xBA:('TSX','imp',1), 0xBC:('LDY','abx',3),
    0xBD:('LDA','abx',3), 0xBE:('LDX','aby',3), 0xC0:('CPY','imm',2),
    0xC1:('CMP','idx',2), 0xC4:('CPY','zpg',2), 0xC5:('CMP','zpg',2),
    0xC6:('DEC','zpg',2), 0xC8:('INY','imp',1), 0xC9:('CMP','imm',2),
    0xCA:('DEX','imp',1), 0xCC:('CPY','abs',3), 0xCD:('CMP','abs',3),
    0xCE:('DEC','abs',3), 0xD0:('BNE','rel',2), 0xD1:('CMP','idy',2),
    0xD5:('CMP','zpx',2), 0xD6:('DEC','zpx',2), 0xD8:('CLD','imp',1),
    0xD9:('CMP','aby',3), 0xDD:('CMP','abx',3), 0xDE:('DEC','abx',3),
    0xE0:('CPX','imm',2), 0xE1:('SBC','idx',2), 0xE4:('CPX','zpg',2),
    0xE5:('SBC','zpg',2), 0xE6:('INC','zpg',2), 0xE8:('INX','imp',1),
    0xE9:('SBC','imm',2), 0xEA:('NOP','imp',1), 0xEC:('CPX','abs',3),
    0xED:('SBC','abs',3), 0xEE:('INC','abs',3), 0xF0:('BEQ','rel',2),
    0xF1:('SBC','idy',2), 0xF5:('SBC','zpx',2), 0xF6:('INC','zpx',2),
    0xF8:('SED','imp',1), 0xF9:('SBC','aby',3), 0xFD:('SBC','abx',3),
    0xFE:('INC','abx',3),
}
_65C02_EXTRA: dict[int, tuple[str, str, int]] = {
    0x04:('TSB','zpg',2), 0x0C:('TSB','abs',3), 0x12:('ORA','zpi',2),
    0x14:('TRB','zpg',2), 0x1A:('INC','acc',1), 0x1C:('TRB','abs',3),
    0x32:('AND','zpi',2), 0x34:('BIT','zpx',2), 0x3A:('DEC','acc',1),
    0x3C:('BIT','abx',3), 0x52:('EOR','zpi',2), 0x5A:('PHY','imp',1),
    0x64:('STZ','zpg',2), 0x72:('ADC','zpi',2), 0x74:('STZ','zpx',2),
    0x7A:('PLY','imp',1), 0x80:('BRA','rel', 2), 0x89:('BIT','imm',2),
    0x92:('STA','zpi',2), 0x9C:('STZ','abs',3), 0x9E:('STZ','abx',3),
    0xB2:('LDA','zpi',2), 0xD2:('CMP','zpi',2), 0xDA:('PHX','imp',1),
    0xF2:('SBC','zpi',2), 0xFA:('PLX','imp',1),
}

def _fmt_6502(mn: str, mode: str, raw: bytes, pc: int) -> str:
    o = raw[1] if len(raw) > 1 else 0
    w = (raw[1] | raw[2] << 8) if len(raw) > 2 else 0
    rel = pc + 2 + (o if o < 128 else o - 256)
    return {
        'imp': mn,
        'acc': f'{mn} A',
        'imm': f'{mn} #${o:02X}',
        'zpg': f'{mn} ${o:02X}',
        'zpx': f'{mn} ${o:02X},X',
        'zpy': f'{mn} ${o:02X},Y',
        'abs': f'{mn} ${w:04X}',
        'abx': f'{mn} ${w:04X},X',
        'aby': f'{mn} ${w:04X},Y',
        'ind': f'{mn} (${w:04X})',
        'idx': f'{mn} (${o:02X},X)',
        'idy': f'{mn} (${o:02X}),Y',
        'zpi': f'{mn} (${o:02X})',
        'rel': f'{mn} ${rel:04X}',
    }.get(mode, f'{mn} ?')

def _disasm_6502(data: bytes, base: int, is_65c02: bool) -> list[tuple[int,str,str]]:
    ops = dict(_6502_OPS)
    if is_65c02:
        ops.update(_65C02_EXTRA)
    rows, i = [], 0
    while i < len(data):
        b = data[i]
        if b in ops:
            mn, mode, sz = ops[b]
            raw = data[i:i+sz]
            if len(raw) < sz:
                rows.append((base+i, ' '.join(f'{x:02X}' for x in raw), '???'))
                break
            asm = _fmt_6502(mn, mode, raw, base+i)
        else:
            raw = data[i:i+1]
            asm = f'??? (${b:02X})'
            sz = 1
        rows.append((base+i, ' '.join(f'{x:02X}' for x in raw), asm))
        i += sz
    return rows

def _disasm_ndisasm(data: bytes, base: int, bits: int) -> list[tuple[int,str,str]]:
    if not shutil.which('ndisasm'):
        return []
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(data); tmp = f.name
    try:
        r = subprocess.run(
            ['ndisasm', f'-b{bits}', f'-o{base:#x}', tmp],
            capture_output=True, text=True, timeout=10)
        rows = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3:
                try:
                    addr = int(parts[0], 16)
                    rows.append((addr, parts[1], parts[2]))
                except ValueError:
                    pass
        return rows
    except Exception:
        return []
    finally:
        os.unlink(tmp)


# ── Export helpers ─────────────────────────────────────────────────────────

def _to_intel_hex(data: bytes, base: int = 0) -> str:
    lines, bpl = [], 16
    for i in range(0, len(data), bpl):
        chunk = data[i:i+bpl]
        addr = (base + i) & 0xFFFF
        rec = [len(chunk), addr >> 8, addr & 0xFF, 0x00] + list(chunk)
        cs = (-sum(rec)) & 0xFF
        lines.append(':' + ''.join(f'{b:02X}' for b in rec) + f'{cs:02X}')
    lines.append(':00000001FF')
    return '\n'.join(lines)

def _to_srec(data: bytes, base: int = 0) -> str:
    lines, bpl = [], 16
    hdr = b'minipro-gui'
    r = bytes([len(hdr)+3, 0, 0]) + hdr
    lines.append('S0' + r.hex().upper() + f'{(-sum(r))&0xFF:02X}')
    for i in range(0, len(data), bpl):
        chunk = data[i:i+bpl]
        addr = base + i
        if addr <= 0xFFFF:
            ab = bytes([addr>>8, addr&0xFF]); t = 'S1'
        elif addr <= 0xFFFFFF:
            ab = bytes([addr>>16, (addr>>8)&0xFF, addr&0xFF]); t = 'S2'
        else:
            ab = bytes([addr>>24,(addr>>16)&0xFF,(addr>>8)&0xFF,addr&0xFF]); t='S3'
        rec = bytes([len(ab)+len(chunk)+1]) + ab + chunk
        lines.append(t + rec.hex().upper() + f'{(-sum(rec))&0xFF:02X}')
    lines.append('S9030000FC')
    return '\n'.join(lines)

def _to_c_array(data: bytes, name: str = 'rom') -> str:
    lines = [f'const uint8_t {name}[{len(data)}] = {{']
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        row = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(f'    {row},')
    lines.append('};')
    return '\n'.join(lines)

def _to_python(data: bytes, name: str = 'rom') -> str:
    lines = [f'{name} = bytes([']
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        row = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(f'    {row},')
    lines.append('])')
    return '\n'.join(lines)


# ── Entropy view ───────────────────────────────────────────────────────────

class EntropyView(Gtk.Box):
    """Bar chart of per-block Shannon entropy."""

    BLOCK_SIZES = [64, 128, 256, 512, 1024]

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''
        self._hover_x: float = -1

        ctrl = Gtk.Box(spacing=8, margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)
        ctrl.append(Gtk.Label(label='Block size:'))
        self._block_drop = Gtk.DropDown(
            model=Gtk.StringList.new([str(s) for s in self.BLOCK_SIZES]))
        self._block_drop.set_selected(2)   # 256 bytes default
        self._block_drop.connect('notify::selected',
                                 lambda *_: self._area.queue_draw())
        ctrl.append(self._block_drop)

        # Legend
        for label, color in [('Low/blank','#3359e5'),
                              ('Code/data','#33cc55'),
                              ('Compressed/encrypted','#e53333')]:
            dot = Gtk.Label()
            dot.set_markup(f'<span foreground="{color}">■</span> {label}')
            ctrl.append(dot)

        self._info = Gtk.Label(label='', xalign=0, hexpand=True,
                               css_classes=['dim-label'])
        ctrl.append(self._info)
        self.append(ctrl)
        self.append(Gtk.Separator())

        self._area = Gtk.DrawingArea(vexpand=True, hexpand=True)
        self._area.set_draw_func(self._draw)

        motion = Gtk.EventControllerMotion()
        motion.connect('motion', self._on_motion)
        motion.connect('leave', self._on_leave)
        self._area.add_controller(motion)

        self.append(self._area)

    def update(self, data: bytes):
        self._data = data
        self._area.queue_draw()

    def _on_motion(self, ctrl, x, y):
        self._hover_x = x
        self._area.queue_draw()

    def _on_leave(self, ctrl):
        self._hover_x = -1
        self._info.set_text('')
        self._area.queue_draw()

    def _draw(self, area, cr, w, h):
        # Background
        cr.set_source_rgb(0.08, 0.08, 0.08)
        cr.rectangle(0, 0, w, h)
        cr.fill()

        if not self._data:
            return

        bsz = self.BLOCK_SIZES[self._block_drop.get_selected()]
        blocks = [self._data[i:i+bsz]
                  for i in range(0, len(self._data), bsz)]
        entropies = [_block_entropy(b) for b in blocks]
        n = len(entropies)
        if n == 0:
            return

        bw = w / n
        for i, e in enumerate(entropies):
            bh = (e / 8.0) * (h - 20)
            r, g, b = _entropy_color(e)
            cr.set_source_rgb(r, g, b)
            cr.rectangle(i * bw, h - 20 - bh, max(bw - 1, 1), bh)
            cr.fill()

        # X-axis tick labels (every ~64 blocks)
        cr.set_source_rgb(0.5, 0.5, 0.5)
        cr.set_font_size(9)
        step = max(1, n // 8)
        for i in range(0, n, step):
            x = i * bw
            cr.move_to(x + 2, h - 4)
            cr.show_text(f'{i*bsz:X}')

        # Hover info
        if 0 <= self._hover_x <= w:
            idx = int(self._hover_x / bw)
            if idx < n:
                e = entropies[idx]
                offset = idx * bsz
                self._info.set_text(
                    f'Offset {offset:#010x}  block {idx}  '
                    f'entropy {e:.3f} bits/byte')
                # Vertical cursor
                cr.set_source_rgba(1, 1, 1, 0.3)
                cr.rectangle(idx * bw, 0, max(bw, 1), h - 20)
                cr.fill()


# ── Histogram view ─────────────────────────────────────────────────────────

class HistogramView(Gtk.Box):
    """Bar chart of byte value frequency (all 256 values)."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''
        self._hover_x: float = -1

        ctrl = Gtk.Box(spacing=8, margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)
        self._log_btn = Gtk.ToggleButton(label='Log scale')
        self._log_btn.connect('toggled', lambda *_: self._area.queue_draw())
        ctrl.append(self._log_btn)

        for label, color in [('0x00','#3359e5'), ('Printable','#33cc55'),
                              ('0xFF','#e53333'), ('Other','#888888')]:
            dot = Gtk.Label()
            dot.set_markup(f'<span foreground="{color}">■</span> {label}')
            ctrl.append(dot)

        self._info = Gtk.Label(label='', xalign=0, hexpand=True,
                               css_classes=['dim-label'])
        ctrl.append(self._info)
        self.append(ctrl)
        self.append(Gtk.Separator())

        self._area = Gtk.DrawingArea(vexpand=True, hexpand=True)
        self._area.set_draw_func(self._draw)

        motion = Gtk.EventControllerMotion()
        motion.connect('motion', self._on_motion)
        motion.connect('leave', self._on_leave)
        self._area.add_controller(motion)

        self.append(self._area)

    def update(self, data: bytes):
        self._data = data
        self._area.queue_draw()

    def _on_motion(self, ctrl, x, y):
        self._hover_x = x
        self._area.queue_draw()

    def _on_leave(self, ctrl):
        self._hover_x = -1
        self._info.set_text('')
        self._area.queue_draw()

    def _draw(self, area, cr, w, h):
        cr.set_source_rgb(0.08, 0.08, 0.08)
        cr.rectangle(0, 0, w, h)
        cr.fill()

        if not self._data:
            return

        counts = [0] * 256
        for b in self._data:
            counts[b] += 1

        log_scale = self._log_btn.get_active()
        max_c = max(counts) or 1
        chart_h = h - 20

        bw = w / 256
        for i, c in enumerate(counts):
            if c == 0:
                continue
            norm = (math.log1p(c) / math.log1p(max_c)) if log_scale else (c / max_c)
            bh = norm * chart_h
            if i == 0x00:
                r, g, b = 0.2, 0.3, 0.9
            elif i == 0xFF:
                r, g, b = 0.9, 0.2, 0.2
            elif 0x20 <= i <= 0x7E:
                r, g, b = 0.2, 0.8, 0.3
            else:
                r, g, b = 0.55, 0.55, 0.55
            cr.set_source_rgb(r, g, b)
            cr.rectangle(i * bw, h - 20 - bh, max(bw - 0.5, 0.5), bh)
            cr.fill()

        # X-axis labels every 16 bytes
        cr.set_source_rgb(0.5, 0.5, 0.5)
        cr.set_font_size(9)
        for i in range(0, 256, 16):
            cr.move_to(i * bw + 1, h - 4)
            cr.show_text(f'{i:02X}')

        # Hover
        if 0 <= self._hover_x <= w:
            idx = min(int(self._hover_x / bw), 255)
            c = counts[idx]
            pct = c / len(self._data) * 100 if self._data else 0
            self._info.set_text(
                f'Byte 0x{idx:02X} ({idx:3d})  '
                f'count {c:,}  ({pct:.2f}%)')
            cr.set_source_rgba(1, 1, 1, 0.25)
            cr.rectangle(idx * bw, 0, max(bw, 1), chart_h)
            cr.fill()


# ── Disassembler view ──────────────────────────────────────────────────────

class DisasmView(Gtk.Box):
    """Disassembles the buffer for a selectable architecture."""

    ARCHS = ['6502', '65C02', '8086 (16-bit)', 'x86 (32-bit)']

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''

        ctrl = Gtk.Box(spacing=8, margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)
        ctrl.append(Gtk.Label(label='Architecture:'))
        self._arch_drop = Gtk.DropDown(
            model=Gtk.StringList.new(self.ARCHS))
        ctrl.append(self._arch_drop)

        ctrl.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        ctrl.append(Gtk.Label(label='Start offset:'))
        self._offset_entry = Gtk.Entry(
            text='0', max_width_chars=10, width_chars=10,
            tooltip_text='Hex offset into buffer')
        ctrl.append(self._offset_entry)

        ctrl.append(Gtk.Label(label='Bytes:'))
        self._len_entry = Gtk.Entry(
            text='256', max_width_chars=8, width_chars=8,
            tooltip_text='Number of bytes to disassemble (decimal)')
        ctrl.append(self._len_entry)

        go_btn = Gtk.Button(label='Disassemble')
        go_btn.connect('clicked', self._on_go)
        ctrl.append(go_btn)

        self._status = Gtk.Label(label='', xalign=0, hexpand=True,
                                 css_classes=['dim-label'])
        ctrl.append(self._status)
        self.append(ctrl)
        self.append(Gtk.Separator())

        self._store = Gtk.ListStore(str, str, str)
        tv = Gtk.TreeView(model=self._store)
        tv.set_headers_visible(True)
        tv.set_enable_search(False)
        tv.add_css_class('hex-view')

        for title, idx, w in [('Offset',0,80), ('Bytes',1,140), ('Assembly',2,-1)]:
            r = Gtk.CellRendererText()
            c = Gtk.TreeViewColumn(title, r, text=idx)
            c.set_resizable(True)
            if w > 0:
                c.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                c.set_fixed_width(w)
            else:
                c.set_expand(True)
            tv.append_column(c)

        scroll = Gtk.ScrolledWindow(
            vexpand=True, hexpand=True,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        scroll.set_child(tv)
        self.append(scroll)

    def update(self, data: bytes):
        self._data = data
        self._store.clear()
        self._status.set_text('')

    def _on_go(self, _btn):
        if not self._data:
            self._status.set_text('No data loaded.')
            return
        try:
            offset = int(self._offset_entry.get_text().strip(), 16)
            length = int(self._len_entry.get_text().strip(), 10)
        except ValueError:
            self._status.set_text('Invalid offset or length.')
            return

        chunk = self._data[offset:offset+length]
        if not chunk:
            self._status.set_text('Offset out of range.')
            return

        arch = self.ARCHS[self._arch_drop.get_selected()]
        if arch == '6502':
            rows = _disasm_6502(chunk, offset, False)
        elif arch == '65C02':
            rows = _disasm_6502(chunk, offset, True)
        elif arch == '8086 (16-bit)':
            rows = _disasm_ndisasm(chunk, offset, 16)
            if not rows:
                self._status.set_text('ndisasm not found — install nasm.')
                return
        else:
            rows = _disasm_ndisasm(chunk, offset, 32)
            if not rows:
                self._status.set_text('ndisasm not found — install nasm.')
                return

        self._store.clear()
        for addr, raw, asm in rows:
            self._store.append([f'{addr:08X}', raw, asm])
        self._status.set_text(f'{len(rows)} instructions')


# ── Export view ────────────────────────────────────────────────────────────

class ExportView(Gtk.Box):
    """Convert and save the buffer in various formats."""

    FORMATS = ['Intel HEX', 'Motorola S-Record', 'C Array', 'Python bytes']

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''

        ctrl = Gtk.Box(spacing=8, margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)
        ctrl.append(Gtk.Label(label='Format:'))
        self._fmt_drop = Gtk.DropDown(
            model=Gtk.StringList.new(self.FORMATS))
        self._fmt_drop.connect('notify::selected', self._on_settings)
        ctrl.append(self._fmt_drop)

        ctrl.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        ctrl.append(Gtk.Label(label='Base address:'))
        self._base_entry = Gtk.Entry(
            text='0000', max_width_chars=10, width_chars=10)
        self._base_entry.connect('changed', self._on_settings)
        ctrl.append(self._base_entry)

        ctrl.append(Gtk.Label(label='Variable name:'))
        self._name_entry = Gtk.Entry(
            text='rom', max_width_chars=12, width_chars=12)
        self._name_entry.connect('changed', self._on_settings)
        ctrl.append(self._name_entry)

        save_btn = Gtk.Button(label='Save…')
        save_btn.connect('clicked', self._on_save)
        ctrl.append(save_btn)

        clip_btn = Gtk.Button(label='Copy')
        clip_btn.connect('clicked', self._on_copy)
        ctrl.append(clip_btn)

        self.append(ctrl)
        self.append(Gtk.Separator())

        self._preview = Gtk.TextView(
            editable=False, monospace=True,
            left_margin=6, right_margin=6, top_margin=6, bottom_margin=6,
            vexpand=True, hexpand=True,
        )
        self._preview_buf = self._preview.get_buffer()
        scroll = Gtk.ScrolledWindow(
            vexpand=True, hexpand=True,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        scroll.set_child(self._preview)
        self.append(scroll)

    def update(self, data: bytes):
        self._data = data
        self._refresh_preview()

    def _on_settings(self, *_):
        self._refresh_preview()

    def _get_text(self) -> str:
        if not self._data:
            return ''
        try:
            base = int(self._base_entry.get_text().strip() or '0', 16)
        except ValueError:
            base = 0
        name = self._name_entry.get_text().strip() or 'rom'
        fmt = self.FORMATS[self._fmt_drop.get_selected()]
        if fmt == 'Intel HEX':
            return _to_intel_hex(self._data, base)
        elif fmt == 'Motorola S-Record':
            return _to_srec(self._data, base)
        elif fmt == 'C Array':
            return _to_c_array(self._data, name)
        else:
            return _to_python(self._data, name)

    def _refresh_preview(self):
        text = self._get_text()
        # Show first 100 lines in preview
        lines = text.splitlines()
        preview = '\n'.join(lines[:100])
        if len(lines) > 100:
            preview += f'\n... ({len(lines)-100} more lines)'
        self._preview_buf.set_text(preview)

    def _on_save(self, _btn):
        fmt = self.FORMATS[self._fmt_drop.get_selected()]
        ext = {
            'Intel HEX': '.hex', 'Motorola S-Record': '.srec',
            'C Array': '.c', 'Python bytes': '.py',
        }[fmt]
        dlg = Gtk.FileDialog(title='Save export')
        dlg.set_initial_name(f'rom{ext}')
        root = self.get_root()
        dlg.save(root if isinstance(root, Gtk.Window) else None,
                 None, self._save_cb)

    def _save_cb(self, dlg, result):
        try:
            path = dlg.save_finish(result).get_path()
            with open(path, 'w') as f:
                f.write(self._get_text())
        except Exception:
            pass

    def _on_copy(self, _btn):
        text = self._get_text()
        display = Gdk.Display.get_default()
        display.get_clipboard().set(text)


# ── Device info panel ──────────────────────────────────────────────────────

class DeviceInfoView(Gtk.Box):
    """Panel showing chip metadata and statistics for the loaded buffer."""

    def __init__(self):
        super().__init__(
            orientation=Gtk.Orientation.VERTICAL, spacing=0,
            margin_start=12, margin_end=12, margin_top=8, margin_bottom=8,
        )

        grid = Gtk.Grid(row_spacing=6, column_spacing=16)
        self.append(grid)

        self._vals: dict[str, Gtk.Label] = {}
        fields = [
            ('Device',      'IC name and package'),
            ('Size',        'Buffer size in bytes'),
            ('Checksum',    '16-bit sum of all bytes (matches XGpro ChkSum)'),
            ('CRC32',       '32-bit CRC of the buffer'),
            ('Blank bytes', 'Bytes equal to 0xFF'),
            ('Data bytes',  'Non-blank bytes'),
        ]
        for row, (name, tooltip) in enumerate(fields):
            lbl = Gtk.Label(label=name + ':', xalign=1.0,
                            css_classes=['dim-label'])
            val = Gtk.Label(label='—', xalign=0.0, selectable=True,
                            hexpand=True, tooltip_text=tooltip)
            val.set_markup('<span font_family="monospace">—</span>')
            grid.attach(lbl, 0, row, 1, 1)
            grid.attach(val, 1, row, 1, 1)
            self._vals[name] = val

    def _mono(self, text: str) -> str:
        return f'<span font_family="monospace">{GLib.markup_escape_text(text)}</span>'

    def update(self, device: str, data: bytes):
        if device:
            pkg = device.split('@')[1] if '@' in device else ''
            self._vals['Device'].set_markup(
                self._mono(device.split('@')[0]) +
                (f'  <span foreground="#888888">@{pkg}</span>' if pkg else '')
            )
        else:
            self._vals['Device'].set_markup(self._mono('—'))

        if not data:
            for k in ('Size', 'Checksum', 'CRC32', 'Blank bytes', 'Data bytes'):
                self._vals[k].set_markup(self._mono('—'))
            return

        size = len(data)
        self._vals['Size'].set_markup(
            self._mono(f'{size:,} bytes  ({size:#010x})')
        )

        # 16-bit checksum: sum of all bytes truncated to 16 bits (XGpro-style)
        chk = sum(data) & 0xFFFF
        self._vals['Checksum'].set_markup(self._mono(f'{chk:#06x}'))

        crc = zlib.crc32(data) & 0xFFFFFFFF
        self._vals['CRC32'].set_markup(self._mono(f'{crc:#010x}'))

        blank = data.count(0xFF)
        nonblank = size - blank
        self._vals['Blank bytes'].set_markup(
            self._mono(f'{blank:,}  ({blank/size*100:.1f}%)')
        )
        self._vals['Data bytes'].set_markup(
            self._mono(f'{nonblank:,}  ({nonblank/size*100:.1f}%)')
        )


# ── Strings view ──────────────────────────────────────────────────────────

class StringsView(Gtk.Box):
    """Extracts and displays printable strings from the loaded buffer."""

    MIN_LEN_DEFAULT = 4

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''

        # ── controls ──────────────────────────────────────────────────
        ctrl = Gtk.Box(spacing=8,
                       margin_start=8, margin_end=8,
                       margin_top=4, margin_bottom=4)

        ctrl.append(Gtk.Label(label='Min length:'))

        self._min_spin = Gtk.SpinButton(
            adjustment=Gtk.Adjustment(
                value=self.MIN_LEN_DEFAULT,
                lower=1, upper=256, step_increment=1, page_increment=4,
            ),
            numeric=True, digits=0,
        )
        self._min_spin.connect('value-changed', self._on_settings_changed)
        ctrl.append(self._min_spin)

        ctrl.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

        self._filter_entry = Gtk.SearchEntry(
            placeholder_text='Filter strings…', hexpand=True)
        self._filter_entry.connect('search-changed', self._on_filter_changed)
        ctrl.append(self._filter_entry)

        self._count_lbl = Gtk.Label(
            label='', xalign=1.0, css_classes=['dim-label'])
        ctrl.append(self._count_lbl)

        self.append(ctrl)
        self.append(Gtk.Separator())

        # ── list store: offset (str), length (str), string (str) ──────
        self._store = Gtk.ListStore(str, str, str)

        self._filter_model = self._store.filter_new()
        self._filter_model.set_visible_func(self._row_visible)

        tv = Gtk.TreeView(model=self._filter_model)
        tv.set_headers_visible(True)
        tv.set_enable_search(False)
        tv.add_css_class('hex-view')   # reuse monospace CSS

        cols = [
            ('Offset',  0, 80,  0.0),
            ('Length',  1, 50,  1.0),
            ('String',  2, -1,  0.0),
        ]
        for title, col_idx, width, xalign in cols:
            r = Gtk.CellRendererText()
            r.set_property('xalign', xalign)
            c = Gtk.TreeViewColumn(title, r, text=col_idx)
            c.set_resizable(True)
            if width > 0:
                c.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                c.set_fixed_width(width)
            else:
                c.set_expand(True)
            tv.append_column(c)

        scroll = Gtk.ScrolledWindow(
            vexpand=True, hexpand=True,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        scroll.set_child(tv)
        self.append(scroll)

    # ── filtering ──────────────────────────────────────────────────────

    def _row_visible(self, model, it, _):
        needle = self._filter_entry.get_text().lower()
        if not needle:
            return True
        return needle in model.get_value(it, 2).lower()

    def _on_filter_changed(self, _entry):
        self._filter_model.refilter()
        self._update_count()

    def _on_settings_changed(self, _spin):
        self._refresh()

    # ── data loading ───────────────────────────────────────────────────

    def update(self, data: bytes):
        self._data = data
        self._refresh()

    def _refresh(self):
        self._store.clear()
        self._count_lbl.set_text('')
        if not self._data:
            return

        min_len = int(self._min_spin.get_value())
        strings = list(self._extract(self._data, min_len))

        for offset, s in strings:
            self._store.append([f'{offset:08X}', str(len(s)), s])

        self._update_count()

    def _update_count(self):
        total = len(self._store)
        visible = self._filter_model.iter_n_children(None)
        if self._filter_entry.get_text():
            self._count_lbl.set_text(f'{visible} of {total} strings')
        else:
            self._count_lbl.set_text(f'{total} strings')

    @staticmethod
    def _extract(data: bytes, min_len: int):
        """Yield (offset, string) for every printable ASCII run >= min_len bytes."""
        start = None
        for i, b in enumerate(data):
            if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):  # printable + tab/LF/CR
                if start is None:
                    start = i
            else:
                if start is not None:
                    s = data[start:i].decode('ascii', errors='replace')
                    s = s.replace('\t', '→').replace('\n', '↵').replace('\r', '')
                    if len(s.strip()) >= min_len:
                        yield start, s.rstrip()
                    start = None
        if start is not None:
            s = data[start:].decode('ascii', errors='replace')
            s = s.replace('\t', '→').replace('\n', '↵').replace('\r', '')
            if len(s.strip()) >= min_len:
                yield start, s.rstrip()


# ── Hex viewer widget ──────────────────────────────────────────────────────

class HexView(Gtk.Box):
    """XGpro-style hex buffer viewer with 8/16-bit modes and diff highlighting."""

    BYTES_PER_ROW = 16

    def __init__(self, on_data_loaded=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._data: bytes = b''
        self._cmp_data: bytes = b''
        self._diff_rows: list[set] = []
        self._mode_16bit: bool = False
        self._on_data_loaded = on_data_loaded
        self._file_path: str = ''

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

        self._cmp_btn = Gtk.Button(label='Compare…',
                                   tooltip_text='Load a second file to diff against the buffer')
        self._cmp_btn.connect('clicked', self._on_compare_file)
        ctrl.append(self._cmp_btn)

        self._clear_cmp_btn = Gtk.Button(label='Clear Compare',
                                          css_classes=['destructive-action'])
        self._clear_cmp_btn.set_visible(False)
        self._clear_cmp_btn.connect('clicked', self._on_clear_compare)
        ctrl.append(self._clear_cmp_btn)

        edit_btn = Gtk.Button(label='Edit Buffer…',
                              tooltip_text='Fill ranges or patch individual bytes')
        edit_btn.connect('clicked', self._on_edit)
        ctrl.append(edit_btn)

        self._info_lbl = Gtk.Label(
            label='No data loaded', xalign=0, hexpand=True,
            css_classes=['dim-label'],
        )
        ctrl.append(self._info_lbl)

        self._diff_lbl = Gtk.Label(label='', xalign=1.0)
        ctrl.append(self._diff_lbl)

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

    def _make_diff_func(self, byte_indices: list[int]):
        """Cell data function that highlights cells where bytes differ."""
        def func(col, renderer, model, it, _):
            if not self._diff_rows:
                renderer.set_property('foreground-set', False)
                renderer.set_property('background-set', False)
                return
            row_idx = model.get_path(it).get_indices()[0]
            if row_idx >= len(self._diff_rows):
                renderer.set_property('foreground-set', False)
                renderer.set_property('background-set', False)
                return
            if any(i in self._diff_rows[row_idx] for i in byte_indices):
                renderer.set_property('foreground', '#ff6666')
                renderer.set_property('background', '#3a1010')
                renderer.set_property('foreground-set', True)
                renderer.set_property('background-set', True)
            else:
                renderer.set_property('foreground-set', False)
                renderer.set_property('background-set', False)
        return func

    def _rebuild_columns(self):
        for col in list(self._tv.get_columns()):
            self._tv.remove_column(col)

        # Address column — blue
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
                col.set_cell_data_func(r, self._make_diff_func([i]))
                self._tv.append_column(col)
        else:
            for i, hdr in enumerate(_HEX_HDRS_16):
                r = Gtk.CellRendererText()
                r.set_property('xalign', 0.5)
                col = Gtk.TreeViewColumn(hdr, r, text=i + 1)
                col.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
                col.set_fixed_width(40)
                col.set_cell_data_func(r, self._make_diff_func([i * 2, i * 2 + 1]))
                self._tv.append_column(col)

        # ASCII column
        r = Gtk.CellRendererText()
        r.set_property('foreground', '#888888')
        col = Gtk.TreeViewColumn('ASCII', r, text=17)
        self._tv.append_column(col)

    # ── mode toggle ────────────────────────────────────────────────────

    def _on_mode_toggled(self, btn):
        if not btn.get_active():
            return
        self._mode_16bit = (btn is self._btn16)
        self._rebuild_columns()
        self._refresh()

    # ── file loading ───────────────────────────────────────────────────

    def _on_open_file(self, _btn):
        dlg = Gtk.FileDialog(title='Open binary file')
        root = self.get_root()
        dlg.open(root if isinstance(root, Gtk.Window) else None, None, self._open_cb)

    def _open_cb(self, dlg, result):
        try:
            f = dlg.open_finish(result)
            self.load_file(f.get_path())
        except Exception:
            pass

    def _on_compare_file(self, _btn):
        dlg = Gtk.FileDialog(title='Open file to compare against buffer')
        root = self.get_root()
        dlg.open(root if isinstance(root, Gtk.Window) else None, None, self._cmp_open_cb)

    def _cmp_open_cb(self, dlg, result):
        try:
            f = dlg.open_finish(result)
            with open(f.get_path(), 'rb') as fh:
                self._cmp_data = fh.read()
            self._compute_diff()
            self._refresh()
            self._clear_cmp_btn.set_visible(True)
        except Exception as exc:
            self._info_lbl.set_text(f'Compare error: {exc}')

    def _on_clear_compare(self, _btn):
        self._cmp_data = b''
        self._diff_rows = []
        self._diff_lbl.set_label('')
        self._clear_cmp_btn.set_visible(False)
        self._refresh()

    def load_file(self, path: str):
        try:
            with open(path, 'rb') as fh:
                self._file_path = path
                self.load_bytes(fh.read())
        except Exception as exc:
            self._info_lbl.set_text(f'Error loading file: {exc}')

    def load_bytes(self, data: bytes):
        self._data = data
        if self._cmp_data:
            self._compute_diff()
        self._refresh()
        if self._on_data_loaded:
            self._on_data_loaded(data)

    # ── edit buffer ────────────────────────────────────────────────────

    def _on_edit(self, _btn):
        root = self.get_root()
        dlg = Gtk.Window(
            title='Edit Buffer',
            transient_for=root if isinstance(root, Gtk.Window) else None,
            modal=True, default_width=380,
        )
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                      margin_start=12, margin_end=12,
                      margin_top=12, margin_bottom=12)
        dlg.set_child(box)

        # Fill range
        box.append(Gtk.Label(label='Fill Range', xalign=0,
                             attributes=self._bold_attrs()))
        fg = Gtk.Grid(row_spacing=6, column_spacing=8)
        fg.attach(Gtk.Label(label='Start (hex):', xalign=1), 0, 0, 1, 1)
        start_e = Gtk.Entry(text='00000000', max_width_chars=10, width_chars=10)
        fg.attach(start_e, 1, 0, 1, 1)
        fg.attach(Gtk.Label(label='End (hex):', xalign=1), 0, 1, 1, 1)
        end_e = Gtk.Entry(text='00000010', max_width_chars=10, width_chars=10)
        fg.attach(end_e, 1, 1, 1, 1)
        fg.attach(Gtk.Label(label='Value (hex):', xalign=1), 0, 2, 1, 1)
        fill_e = Gtk.Entry(text='FF', max_width_chars=4, width_chars=4)
        fg.attach(fill_e, 1, 2, 1, 1)
        fill_btn = Gtk.Button(label='Apply Fill',
                              css_classes=['suggested-action'],
                              halign=Gtk.Align.END)
        fg.attach(fill_btn, 1, 3, 1, 1)
        box.append(fg)

        box.append(Gtk.Separator())

        # Patch byte
        box.append(Gtk.Label(label='Patch Byte', xalign=0,
                             attributes=self._bold_attrs()))
        pg = Gtk.Grid(row_spacing=6, column_spacing=8)
        pg.attach(Gtk.Label(label='Offset (hex):', xalign=1), 0, 0, 1, 1)
        poff_e = Gtk.Entry(text='00000000', max_width_chars=10, width_chars=10)
        pg.attach(poff_e, 1, 0, 1, 1)
        pg.attach(Gtk.Label(label='Value (hex):', xalign=1), 0, 1, 1, 1)
        pval_e = Gtk.Entry(text='00', max_width_chars=4, width_chars=4)
        pg.attach(pval_e, 1, 1, 1, 1)
        patch_btn = Gtk.Button(label='Apply Patch',
                               css_classes=['suggested-action'],
                               halign=Gtk.Align.END)
        pg.attach(patch_btn, 1, 2, 1, 1)
        box.append(pg)

        box.append(Gtk.Separator())

        save_btn = Gtk.Button(label='Save Buffer to File…')
        save_btn.connect('clicked', lambda _: self._save_buffer(dlg))
        box.append(save_btn)

        status = Gtk.Label(label='', xalign=0, css_classes=['dim-label'])
        box.append(status)

        def do_fill(_btn):
            try:
                s = int(start_e.get_text().strip(), 16)
                e = int(end_e.get_text().strip(), 16)
                v = int(fill_e.get_text().strip(), 16)
                assert 0 <= v <= 0xFF
                assert 0 <= s <= e < len(self._data)
            except Exception:
                status.set_text('Invalid fill parameters.')
                return
            buf = bytearray(self._data)
            buf[s:e+1] = bytes([v] * (e - s + 1))
            self._data = bytes(buf)
            self._refresh()
            if self._on_data_loaded:
                self._on_data_loaded(self._data)
            status.set_text(f'Filled {e-s+1} bytes with 0x{v:02X}')

        def do_patch(_btn):
            try:
                off = int(poff_e.get_text().strip(), 16)
                val = int(pval_e.get_text().strip(), 16)
                assert 0 <= val <= 0xFF
                assert 0 <= off < len(self._data)
            except Exception:
                status.set_text('Invalid patch parameters.')
                return
            buf = bytearray(self._data)
            buf[off] = val
            self._data = bytes(buf)
            self._refresh()
            if self._on_data_loaded:
                self._on_data_loaded(self._data)
            status.set_text(f'Patched offset 0x{off:X} → 0x{val:02X}')

        fill_btn.connect('clicked', do_fill)
        patch_btn.connect('clicked', do_patch)
        dlg.present()

    def _save_buffer(self, parent):
        dlg = Gtk.FileDialog(title='Save buffer')
        if self._file_path:
            dlg.set_initial_name(os.path.basename(self._file_path))
        dlg.save(parent, None, self._save_buffer_cb)

    def _save_buffer_cb(self, dlg, result):
        try:
            path = dlg.save_finish(result).get_path()
            with open(path, 'wb') as f:
                f.write(self._data)
            self._file_path = path
        except Exception:
            pass

    @staticmethod
    def _bold_attrs():
        attrs = Pango.AttrList()
        attrs.insert(Pango.attr_weight_new(Pango.Weight.BOLD))
        return attrs

    # ── diff computation ───────────────────────────────────────────────

    def _compute_diff(self):
        d1, d2 = self._data, self._cmp_data
        bpr = self.BYTES_PER_ROW
        self._diff_rows = []
        for row_start in range(0, max(len(d1), len(d2)), bpr):
            chunk1 = d1[row_start:row_start + bpr]
            chunk2 = d2[row_start:row_start + bpr]
            differs: set[int] = set()
            for i in range(max(len(chunk1), len(chunk2))):
                b1 = chunk1[i] if i < len(chunk1) else -1
                b2 = chunk2[i] if i < len(chunk2) else -1
                if b1 != b2:
                    differs.add(i)
            self._diff_rows.append(differs)

        total = sum(len(s) for s in self._diff_rows)
        if total == 0:
            self._diff_lbl.set_markup(
                '<span foreground="#44cc44">● Files identical</span>'
            )
        else:
            self._diff_lbl.set_markup(
                f'<span foreground="#ff6666">● {total:,} bytes differ</span>'
            )

    # ── display refresh ────────────────────────────────────────────────

    def _refresh(self):
        self._store.clear()
        data = self._data

        if not data:
            self._info_lbl.set_text('No data loaded')
            return

        truncated = len(data) > MAX_HEX_ROWS * self.BYTES_PER_ROW
        display = data[:MAX_HEX_ROWS * self.BYTES_PER_ROW] if truncated else data

        size_str = f'{len(data):,} bytes ({len(data):#010x})'
        self._info_lbl.set_text(
            size_str + '  —  showing first 1 MB' if truncated else size_str
        )

        bpr = self.BYTES_PER_ROW
        for row_start in range(0, len(display), bpr):
            chunk = display[row_start:row_start + bpr]

            if self._mode_16bit:
                word_addr = row_start >> 1
                addr_str = f'{word_addr >> 16:04X}-{word_addr & 0xFFFF:04X}'
            else:
                addr_str = f'{row_start:08X}'

            cols = [''] * 16
            if not self._mode_16bit:
                for i, b in enumerate(chunk):
                    cols[i] = f'{b:02X}'
            else:
                for i in range(min(8, len(chunk) // 2)):
                    hi, lo = chunk[i * 2], chunk[i * 2 + 1]
                    cols[i] = f'{hi:02X}{lo:02X}'

            ascii_str = ''.join(
                chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk
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
        self._count_label.set_text(
            f'{total} devices' if n == total else f'{n} of {total} devices'
        )

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
            default_height=720,
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

        grid.attach(self._rlabel('Device:'), 0, row, 1, 1)
        dev_box = Gtk.Box(spacing=4, hexpand=True)
        self._dev_entry = Gtk.Entry(
            placeholder_text='e.g. W25Q64FV@SOP8', hexpand=True)
        self._dev_entry.connect('changed', self._update_preview)
        dev_box.append(self._dev_entry)
        browse_dev = Gtk.Button(label='Browse…')
        browse_dev.connect('clicked', self._on_browse_device)
        dev_box.append(browse_dev)
        grid.attach(dev_box, 1, row, 1, 1)
        row += 1

        grid.attach(self._rlabel('Operation:'), 0, row, 1, 1)
        self._op_drop = Gtk.DropDown(
            model=Gtk.StringList.new(OPERATIONS), hexpand=True)
        self._op_drop.connect('notify::selected', self._on_op_changed)
        grid.attach(self._op_drop, 1, row, 1, 1)
        row += 1

        self._file_lbl = self._rlabel('File:')
        grid.attach(self._file_lbl, 0, row, 1, 1)
        self._file_box = Gtk.Box(spacing=4, hexpand=True)
        self._file_entry = Gtk.Entry(
            placeholder_text='Select a file…', hexpand=True)
        self._file_entry.connect('changed', self._update_preview)
        self._file_box.append(self._file_entry)
        self._file_btn = Gtk.Button(label='Browse…')
        self._file_btn.connect('clicked', self._on_browse_file)
        self._file_box.append(self._file_btn)
        grid.attach(self._file_box, 1, row, 1, 1)
        row += 1

        grid.attach(self._rlabel('Page:'), 0, row, 1, 1)
        row_box = Gtk.Box(spacing=12, hexpand=True)
        self._page_drop = Gtk.DropDown(
            model=Gtk.StringList.new(PAGE_LABELS), hexpand=True)
        self._page_drop.connect('notify::selected', self._update_preview)
        row_box.append(self._page_drop)
        row_box.append(self._rlabel('Format:'))
        self._fmt_drop = Gtk.DropDown(
            model=Gtk.StringList.new(
                ['Auto-detect', 'Intel HEX', 'Motorola S-Record']),
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

        self._run_btn = Gtk.Button(label='▶  Run',
                                   css_classes=['suggested-action'])
        self._run_btn.connect('clicked', self._on_run)
        action_box.append(self._run_btn)

        self._stop_btn = Gtk.Button(label='■  Stop',
                                    css_classes=['destructive-action'],
                                    sensitive=False)
        self._stop_btn.connect('clicked', self._on_stop)
        action_box.append(self._stop_btn)

        root.append(action_box)

        # ── progress bar ───────────────────────────────────────────────
        self._progress = Gtk.ProgressBar(
            show_text=True, text='',
            visible=False,
            margin_start=8, margin_end=8, margin_bottom=4,
        )
        root.append(self._progress)

        # ── notebook: Hex View | Device Info | Log ─────────────────────
        self._notebook = Gtk.Notebook(
            vexpand=True,
            margin_start=8, margin_end=8, margin_bottom=8,
        )

        # Tab 0 — Hex View
        self._hex_view = HexView(on_data_loaded=self._on_hex_data_loaded)
        self._notebook.append_page(self._hex_view, Gtk.Label(label='Hex View'))

        # Tab 1 — Device Info
        self._dev_info = DeviceInfoView()
        dev_info_scroll = Gtk.ScrolledWindow(
            vexpand=True,
            hscrollbar_policy=Gtk.PolicyType.NEVER,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
        )
        dev_info_scroll.set_child(self._dev_info)
        self._notebook.append_page(dev_info_scroll,
                                   Gtk.Label(label='Device Info'))

        # Tab 2 — Strings
        self._strings_view = StringsView()
        self._notebook.append_page(self._strings_view,
                                   Gtk.Label(label='Strings'))

        # Tab 3 — Entropy
        self._entropy_view = EntropyView()
        self._notebook.append_page(self._entropy_view,
                                   Gtk.Label(label='Entropy'))

        # Tab 4 — Histogram
        self._histogram_view = HistogramView()
        self._notebook.append_page(self._histogram_view,
                                   Gtk.Label(label='Histogram'))

        # Tab 5 — Disassembler
        self._disasm_view = DisasmView()
        self._notebook.append_page(self._disasm_view,
                                   Gtk.Label(label='Disasm'))

        # Tab 6 — Export
        self._export_view = ExportView()
        self._notebook.append_page(self._export_view,
                                   Gtk.Label(label='Export'))

        # Tab 7 — Log
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
        self._notebook.append_page(log_box, Gtk.Label(label='Log'))

        root.append(self._notebook)

        self._load_config()
        self._update_preview()

    def _on_hex_data_loaded(self, data: bytes):
        device = self._dev_entry.get_text().strip()
        self._dev_info.update(device, data)
        self._strings_view.update(data)
        self._entropy_view.update(data)
        self._histogram_view.update(data)
        self._disasm_view.update(data)
        self._export_view.update(data)

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
            self._set_status(False,
                f'minipro not found (looked in PATH and '
                f'{os.path.join(here, "minipro", "minipro")})')
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
        dlg = Gtk.FileDialog(
            title='Save file' if op in SAVE_OPS else 'Open file')
        if op in SAVE_OPS:
            device = self._dev_entry.get_text().strip()
            safe = device.replace('@', '_').replace('/', '_') if device else 'dump'
            dlg.set_initial_name(f'{safe}.bin')
            dlg.save(self.window, None, self._file_save_cb)
        else:
            dlg.open(self.window, None, self._file_open_cb)

    def _file_open_cb(self, dlg, result):
        try:
            self._file_entry.set_text(dlg.open_finish(result).get_path())
        except Exception:
            pass

    def _file_save_cb(self, dlg, result):
        try:
            self._file_entry.set_text(dlg.save_finish(result).get_path())
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

        op_flag = {'Read': '-r', 'Write': '-w', 'Verify': '-m'}
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

        if self._chk_icsp_vcc.get_active():   cmd += ['-i']
        elif self._chk_icsp_novcc.get_active(): cmd += ['-I']
        if self._chk_skip_erase.get_active():  cmd += ['-e']
        if self._chk_skip_verify.get_active(): cmd += ['-v']
        if self._chk_skip_id.get_active():     cmd += ['-x']
        if self._chk_cont_id.get_active():     cmd += ['-y']
        if self._chk_no_sz_err.get_active():   cmd += ['-s']
        if self._chk_pin_check.get_active():   cmd += ['-z']
        if self._chk_prot_off.get_active():    cmd += ['-u']
        if self._chk_prot_on.get_active():     cmd += ['-P']

        return cmd

    def _load_config(self):
        try:
            with open(_CONFIG_PATH) as f:
                cfg = json.load(f)
            if cfg.get('device'):
                self._dev_entry.set_text(cfg['device'])
            if cfg.get('file'):
                self._file_entry.set_text(cfg['file'])
            if 'operation' in cfg:
                self._op_drop.set_selected(cfg['operation'])
        except Exception:
            pass

    def _save_config(self):
        cfg = {
            'device':    self._dev_entry.get_text().strip(),
            'file':      self._file_entry.get_text().strip(),
            'operation': self._op_drop.get_selected(),
        }
        try:
            os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
            with open(_CONFIG_PATH, 'w') as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def _update_preview(self, *_):
        cmd = self._build_cmd()
        if not cmd:
            self._cmd_lbl.set_text('')
        else:
            display, skip = [], False
            for tok in cmd:
                if skip:
                    skip = False
                    continue
                if tok in ('--infoic', '--logicic'):
                    skip = True
                    continue
                display.append(tok)
            self._cmd_lbl.set_text('$ ' + ' '.join(display))
        self._save_config()

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
        self._progress.set_fraction(0.0)
        self._progress.set_text('')
        self._progress.set_visible(True)
        self._notebook.set_current_page(7)   # Log tab while running
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

    def _run_finished(self, rc: int):
        self._run_btn.set_sensitive(True)
        self._stop_btn.set_sensitive(False)

        if rc == 0:
            self._progress.set_fraction(1.0)
            self._progress.set_text('Done')
        else:
            self._progress.set_text('Failed' if rc > 0 else 'Cancelled')

        # Hide progress bar after a short delay
        GLib.timeout_add(3000, self._hide_progress)

        # Auto-load hex view on successful Read
        if rc == 0 and self._last_op == 'Read' and self._last_file:
            self._hex_view.load_file(self._last_file)
            self._notebook.set_current_page(0)   # Hex View tab

    def _hide_progress(self):
        self._progress.set_visible(False)
        return False

    def _log(self, text: str):
        # Update progress bar from minipro percentage lines
        m = _PROGRESS_RE.search(text)
        if m:
            op, pct = m.group(1), int(m.group(2))
            self._progress.set_fraction(pct / 100.0)
            self._progress.set_text(f'{op}… {pct}%')
            self._progress.set_visible(True)

        end = self._log_buf.get_end_iter()
        self._log_buf.insert(end, text)
        self._log_buf.move_mark(self._log_end_mark, self._log_buf.get_end_iter())
        self._log_view.scroll_mark_onscreen(self._log_end_mark)
        return False


if __name__ == '__main__':
    import sys
    app = MiniproApp()
    sys.exit(app.run(sys.argv))
