# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec - 教育SRC挖洞工具 GUI单文件版
# 可视化界面，双击即用，无需命令窗口。

from pathlib import Path

PROJECT_ROOT = Path(r"D:\SRC执行器")

a = Analysis(
    [str(PROJECT_ROOT / "gui_app.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "data"), "data"),
        (str(PROJECT_ROOT / "app_icon.ico"), "."),
    ],
    hiddenimports=[
        "data.universities",
        "data",
        "src.config",
        "src.selector",
        "src.recon.asset_collector",
        "src.recon.prober",
        "src.recon.tooling",
        "src.recon.redteam_tools",
        "src.vuln.engine",
        "src.vuln.evidence",
        "src.vuln.nday_verify",
        "src.vuln.poc_index",
        "src.exploit",
        "src.exploit.engine",
        "src.exploit.vectors",
        "src.exploit.checks",
        "src.reverify",
        "src.report.generator",
        "src.report.manager",
        "src.webshell",
        "src.webshell.manager",
        "src.gui",
        "src.gui.enhancements",
        "pandas",
        "pyarrow",
        # tkinter 相关
        "tkinter",
        "tkinter.ttk",
        "tkinter.messagebox",
        "tkinter.filedialog",
        "tkinter.scrolledtext",
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
    name="教育SRC挖洞工具",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # GUI模式，不显示命令行窗口
    disable_windowed_traceback=False,
    icon=str(PROJECT_ROOT / "app_icon.ico"),
)