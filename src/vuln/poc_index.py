# -*- coding: utf-8 -*-
"""PoC源码库索引 - 对接 D:\\漏洞库\\exploitarium

作用：扫描本地PoC源码目录，抽取每个PoC的主题/组件/README摘要，
建立『组件/主题 -> PoC源码路径』的索引，辅助复测时检索可用检测脚本。
全程只读索引本地文件，不执行任何PoC代码。
"""

import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import LOCAL_CVE_PATHS


def index_exploitarium(root=None):
    """扫描exploitarium，返回 [{name, path, blurb}] 列表"""
    root = Path(root or LOCAL_CVE_PATHS.get("exploitarium", ""))
    if not root.exists():
        return []
    projects = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if d.name.startswith("."):  # 跳过 .git 等隐藏目录
            continue
        name = d.name
        readme = d / "README.md"
        blurb = ""
        if readme.exists():
            txt = readme.read_text("utf-8", errors="ignore")[:400]
            # 提取readme标题和首段
            title_m = re.search(r"^#\s+(.+)$", txt, re.M)
            blurb = (title_m.group(1) if title_m else name)
        projects.append({
            "name": name,
            "path": str(d),
            "blurb": blurb,
        })
    return projects


def match_pocs(text, projects=None):
    """根据描述文本，匹配可能相关的本地PoC（基于名称/简介关键词）"""
    if projects is None:
        projects = index_exploitarium()
    if not projects:
        return []
    blob = text.lower()
    hits = []
    for p in projects:
        hay = (p["name"] + " " + p["blurb"]).lower()
        # 共享token匹配
        tokens = {t for t in re.split(r"[^a-z0-9]+", hay) if len(t) > 3}
        for t in tokens:
            if t in blob:
                hits.append(p)
                break
    return hits


if __name__ == "__main__":
    ps = index_exploitarium()
    print(f"exploitarium PoC数量: {len(ps)}")
    for p in ps[:20]:
        print(f"   {p['name']:<42}  {p['blurb'][:30]}")
    print("\n示例匹配 'rce':")
    for m in match_pocs("remote code execution rce vulnerability"):
        print("   ", m["name"])