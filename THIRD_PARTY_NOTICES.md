# Third-party notices

World Forge itself is MIT-licensed. The audited M5 development, asset, and
release toolchain uses these pinned third-party distributions:

- Pillow 12.3.0 — Pillow project, HPND License.
- build 1.5.0 — PyPA build, MIT License.
- cffi 1.17.1 — CFFI project, MIT License.
- pip-audit 2.10.1 — PyPA pip-audit, Apache License 2.0.
- pycparser 2.23 — pycparser project, BSD-3-Clause License.
- raylib 6.0.1.0 — raylib-python-cffi, Eclipse Public License 2.0; bundled raylib uses the zlib/libpng License.
- Ruff 0.15.22 — Astral Ruff, MIT License.
- setuptools 83.0.0 — PyPA setuptools, MIT License.
- wheel 0.47.0 — PyPA wheel, MIT License.

Generated standalone games record their complete install closure, including
CFFI and pycparser, in their own requirements.lock, platform.lock.json, and
THIRD_PARTY_NOTICES.md. Runtime bundles retain separate per-asset license
inventories; this notice does not grant rights to imported media.

The ADR-0050-D2.2a codec sources are original World Forge MIT-licensed code.
Their Linux/aarch64 build dynamically uses the host GNU C Library 2.39, dynamic
loader, GCC/binutils runtime inputs, and Linux UAPI headers. The locked
compiler-tool execution closure also includes the external host libisl, GNU
MPC, GNU MPFR, GNU GMP, zlib, zstd, libopcodes, libbfd, libctf, Jansson, libm,
and libsframe shared libraries plus `/etc/ld.so.cache`. The exact link-input
closure also hashes the installed GCC `liblto_plugin.so` and `lto-wrapper`, the
GNU ld scripts `libgcc_s.so` and `libc.so`, and every regular file those scripts
select, including `libgcc_s.so.1`, `libgcc.a`, `libc.so.6`,
`libc_nonshared.a`, and the dynamic loader. In this non-LTO profile the linker
opens `liblto_plugin.so`; GCC names and stats `lto-wrapper` but does not open or
execute it. These components remain
governed by the installed operating-system packages and their corresponding
license files; World Forge does not redistribute them. Those host
toolchain/runtime inputs are hashed in the build closure but are not bundled in
the source distribution, universal wheel, or native codec archive.
