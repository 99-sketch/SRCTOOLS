# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec - 教育SRC挖洞工具 (onedir 控制台版)

import os
from pathlib import Path

PROJECT_ROOT = Path(r"e:\trae自动化\edu-src-toolkit")

a = Analysis(
    [str(PROJECT_ROOT / "run.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        # 携带高校数据库与文档，确保 exe 主目录含 data
        (str(PROJECT_ROOT / "data"), "data"),
        (str(PROJECT_ROOT / "README.md"), "."),
    ],
    hiddenimports=[
        "data.universities",
        "src.config",
        "src.selector",
        "src.recon.asset_collector",
        "src.recon.prober",
        "src.vuln.engine",
        "src.vuln.poc_index",
        "src.reverify",
        "src.report.generator",
        "src.report.submit_gen",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="edu-src-toolkit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # 需要控制台以支持 input()
    disable_windowed_traceback=False,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="edu-src-toolkit",
)