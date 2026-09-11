# -*- coding: utf-8 -*-
"""全局配置 - 对接本地漏洞库与输出路径"""

import os
import json
import sys
from pathlib import Path

# ============ 工作区根目录（不硬编码本地路径） ============
# 兼容三种运行模式：
#  - 源码运行：脚本所在目录
#  - exe (onedir) 运行：exe所在目录
#  - exe (onefile)运行：exe所在目录（内核解压到临时区，base仍指向exe旁）
if getattr(sys, "frozen", False):
    # PyInstaller 打包环境：使用exe所在目录
    _ROOT_CANDIDATE = Path(sys.executable).resolve().parent
else:
    _ROOT_CANDIDATE = Path(__file__).resolve().parent.parent

# 红线：exe/脚本若位于 C 盘，强制输出回退到 D 盘
def _is_on_c(candidate: Path) -> bool:
    try:
        return candidate.drive.lower() == "c:" or (len(candidate.parts) and candidate.parts[0].lower().startswith("c"))
    except Exception:
        return False

_D_DEV = Path(r"D:\SRC执行器")

def _safe_base(candidate: Path) -> Path:
    """返回输出根目录：优先exe/脚本所在目录(非C盘)，否则退回D盘固定目录"""
    if (_is_on_c(candidate) or not candidate.exists()):
        return _D_DEV
    return candidate

BASE_DIR = _safe_base(_ROOT_CANDIDATE)
OUTPUTS_DIR = BASE_DIR / "outputs"
DATA_DIR = BASE_DIR / "data"
TOOLS_DIR = BASE_DIR / "tools"

for _d in (OUTPUTS_DIR, DATA_DIR, TOOLS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ============ 本地漏洞库（D盘） ============
# 用户实际路径
LOCAL_CVE_PATHS = {
    # 批量CVE/CNVD/NVD/OSV数据
    "cve_root": r"D:\CVE",
    "cnvd":     r"D:\CVE\CNVD\cnvd.parquet",
    "cve_to_cnvd": r"D:\CVE\CNVD\cve_to_cnvd.json",
    # PoC源码集合
    "exploitarium": r"D:\漏洞库\exploitarium",
}
# 允许用户用环境变量覆盖
LOCAL_CVE_PATHS = {
    k: os.environ.get(k.upper().replace("cve_", "EDU_CVE_"), v)
    for k, v in LOCAL_CVE_PATHS.items()
}


# ============ 外部工具（可选） ============
# 这些工具若存在则优先调用加速自动化；不存在则降级为纯Python逻辑
EXTERNAL_TOOLS = {
    "subfinder": "subfinder",
    "nuclei":    "nuclei",
    "httpx":     "httpx",
    "sqlmap":    "sqlmap",
}


def which(tool):
    """检测外部工具是否存在"""
    from shutil import which as _which
    return _which(tool)


def output_dir_for(school_code):
    """为某所学校创建独立输出目录"""
    d = OUTPUTS_DIR / school_code
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_json(path, default=None):
    """安全读取JSON"""
    p = Path(path)
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default