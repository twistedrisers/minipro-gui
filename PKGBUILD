# Maintainer: Adam
pkgname=minipro-gui
pkgver=0.7.4
pkgrel=1
pkgdesc="GTK4 GUI for the minipro chip programmer (TL866II+, T48, T56, T76)"
arch=('x86_64')
url="https://gitlab.com/DavidGriffith/minipro"
license=('GPL3')
depends=('libusb' 'python' 'python-gobject' 'gtk4')
makedepends=('gcc' 'make' 'pkg-config')
install=minipro-gui.install

prepare() {
    cp -a "$startdir/minipro/." "$srcdir/minipro"
    cd "$srcdir/minipro"
    # Force a clean rebuild so SHARE_INSTDIR is compiled in correctly for PREFIX=/usr
    make clean 2>/dev/null || true
}

build() {
    cd "$srcdir/minipro"
    make PREFIX=/usr
}

package() {
    cd "$srcdir/minipro"

    # Install minipro binary, XML data, man page, udev rules, bash completion
    make install \
        DESTDIR="$pkgdir" \
        PREFIX=/usr \
        UDEV_DIR=/usr/lib/udev \
        COMPLETIONS_DIR=/usr/share/bash-completion/completions

    # ── GUI script ────────────────────────────────────────────────────
    install -Dm644 "$startdir/minipro_gui.py" \
        "$pkgdir/usr/share/minipro-gui/minipro_gui.py"

    # ── launcher script ───────────────────────────────────────────────
    install -Dm755 /dev/stdin "$pkgdir/usr/bin/minipro-gui" << 'EOF'
#!/bin/bash
exec python3 /usr/share/minipro-gui/minipro_gui.py "$@"
EOF

    # ── desktop entry ─────────────────────────────────────────────────
    install -Dm644 "$startdir/minipro-gui.desktop" \
        "$pkgdir/usr/share/applications/minipro-gui.desktop"

    # ── icon ──────────────────────────────────────────────────────────
    install -Dm644 "$startdir/TL866II.png" \
        "$pkgdir/usr/share/pixmaps/minipro-gui.png"
}
