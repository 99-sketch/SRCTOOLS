# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec - 教育SRC挖洞工具 单文件版 (onefile)
# 所有功能与数据合并进单个 .exe，双击即用。

from pathlib import Path

PROJECT_ROOT = Path(r"e:\trae自动化\edu-src-toolkit")

a = Analysis(
    [str(PROJECT_ROOT / "run.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        # 高校数据库随包分发到临时解压区 data/（供模块引用）
        (str(PROJECT_ROOT / "data"), "data"),
    ],
    hiddenimports=[
        "data.universities",
        "data",
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
    a.binaries,
    a.datas,
    [],
    name="edu-src-toolkit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,            # 关闭UPX，避免杀软误报
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,         # 需要控制台支持 input()
    disable_windowed_traceback=False,
    icon=None,
)