# -*- coding: utf-8 -*-
"""报告管理器（缓存 + 增删改查 + 路径管理 + 打开/查看）

把每次生成的渗透测试报告登记进一个本地索引(reports_registry.json)，
GUI 内可一键刷新/打开/查看/重命名/删除。所有报告文件统一缓存在
OUTPUTS_DIR/reports/ 下，永不写 C 盘（红线约定）。
"""

import os
import json
import uuid
import time
from pathlib import Path

sys_path_guard = True
import sys
if str(Path(__file__).resolve().parent.parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.config import OUTPUTS_DIR, output_dir_for


REPORTS_CACHE_DIR = OUTPUTS_DIR / "reports"
REGISTRY_FILE = OUTPUTS_DIR / "reports_registry.json"

# 支持打开/查看的报告扩展名
_VIEWABLE_EXTS = (".md", ".html", ".txt", ".json")

_SAFE_LOCK = None


class ReportManager:
    """报告缓存管理器：登记/查询/打开/重命名/删除/查看。"""

    def __init__(self):
        REPORTS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._reg = self._load()

    # ---------------- 内部持久化 ----------------
    def _load(self):
        try:
            if REGISTRY_FILE.exists():
                data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data.get("reports", [])
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return []

    def _save(self):
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        REGISTRY_FILE.write_text(
            json.dumps({"reports": self._reg}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    # ---------------- 增查改删 ----------------
    def register(self, report_path, school=None, summary=None):
        """登记一份新生成/新发现的报告到缓存索引。同路径重复登记会更新。"""
        report_path = Path(report_path).resolve()
        if not report_path.exists():
            return None
        # 统一复制/登记到缓存目录（保持原文件不动，缓存一份副本便于管理）
        rid = str(uuid.uuid4())[:12]
        cached = REPORTS_CACHE_DIR / report_path.name
        try:
            cached.write_bytes(report_path.read_bytes())
        except Exception:
            cached = report_path
        rec = {
            "id": rid,
            "school": (school or {}).get("name", ""),
            "code": (school or {}).get("code", ""),
            "title": (school or {}).get("name", report_path.stem),
            "path": str(report_path),
            "cached": str(cached),
            "ext": report_path.suffix.lower(),
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "confirmed": (summary or {}).get("confirmed_vulns", 0),
            "sev": (summary or {}).get("sev_summary", ""),
            "size": report_path.stat().st_size if report_path.exists() else 0,
        }
        # 已存在同路径则更新记录（保留原id）
        for i, old in enumerate(self._reg):
            if old.get("path") == str(report_path):
                rid = old.get("id", rid)
                rec["id"] = rid
                self._reg[i] = rec
                self._save()
                return rec
        self._reg.insert(0, rec)
        self._save()
        return rec

    def list(self):
        """列出缓存报告（含机器扫出但未登记的 outputs 下的报告可选）。返回列表快照。"""
        snap = list(self._reg)
        # 顺便清理已失效记录
        alive = [r for r in snap if Path(r.get("path", "")).exists() or
                 Path(r.get("cached", "")).exists()]
        if len(alive) != len(snap):
            self._reg = alive
            self._save()
            snap = alive
        return snap

    def rescan_outputs(self, codes=None):
        """扫描 OUTPUTS_DIR 下所有报告文件，自动登记缺失的报告。"""
        from src.config import OUTPUTS_DIR as O
        known = {r.get("path") for r in self._reg}
        added = 0
        for code_dir in O.iterdir():
            if not code_dir.is_dir():
                continue
            if codes and code_dir.name not in codes:
                continue
            for f in code_dir.iterdir():
                if f.is_file() and f.suffix.lower() in _VIEWABLE_EXTS and "report" in f.name.lower():
                    p = str(f.resolve())
                    if p not in known:
                        self.register(p)
                        added += 1
        return added

    def get(self, rid):
        for r in self._reg:
            if r.get("id") == rid:
                return r
        return None

    def update_title(self, rid, new_title):
        r = self.get(rid)
        if not r:
            return None
        r["title"] = new_title.strip() or r.get("title", "")
        self._save()
        return r

    def delete(self, rid):
        r = self.get(rid)
        if not r:
            return False
        self._reg = [x for x in self._reg if x.get("id") != rid]
        self._save()
        # 删除缓存副本（仅删缓存副本，不删用户原始报告）
        try:
            cp = Path(r.get("cached", ""))
            if cp.exists() and cp.resolve() != Path(r.get("path", "")).resolve():
                cp.unlink()
        except Exception:
            pass
        return True

    def open(self, rid):
        """用系统默认程序打开报告（os.startfile）。返回报告当前有效路径。"""
        r = self.get(rid)
        if not r:
            return None
        p = Path(r.get("path", ""))
        if not p.exists():
            p = Path(r.get("cached", ""))
        if not p.exists():
            return None
        try:
            if os.name == "nt":
                os.startfile(str(p))  # noqa
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(p)])
        except Exception:
            return None
        return str(p)

    def read(self, rid, limit=80000):
        """读取报告内容用于查看器。返回 (title, text)。"""
        r = self.get(rid)
        if not r:
            return None, ""
        p = Path(r.get("path", ""))
        if not p.exists():
            p = Path(r.get("cached", ""))
        if not p.exists():
            return None, ""
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            txt = ""
        return r.get("title", p.stem), txt[:limit]


def default_manager():
    _m = getattr(default_manager, "_m", None)
    if _m is None:
        _m = ReportManager()
        default_manager._m = _m
    return _m


if __name__ == "__main__":
    m = default_manager()
    print("报告索引:", m.list())