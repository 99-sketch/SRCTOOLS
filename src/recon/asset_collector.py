# -*- coding: utf-8 -*-
"""信息收集引擎 - 子域名枚举 / 探活 / 指纹识别

设计：
- 优先调用外部工具（subfinder/httpx）加速
- 无外部工具时降级为纯Python逻辑（基于证书透明度、搜索引擎dork辅助）
- 全程只做被动/低强度收集，不触发破坏性动作
"""

import re
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import urllib.request
import ssl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import which, output_dir_for


# ============ 常见子域名前缀（教育单位） ============
EduSubPrefixes = [
    "www", "mail", "vpn", "webvpn", "oa", "cms", "news", "old", "new",
    "lib", "lib1", "lib2", "jwc", "xtw", "sjc", "rsc", "xsc", "scs",
    "zs", "zhaosheng", "stu", "student", "teacher", "admin", "manage",
    "portal", "sso", "cas", "login", "api", "app", "m", "mobile",
    "ftp", "ftp1", "files", "download", "upload", "pay", "epay",
    "moodle", "course", "elearning", "jxb", "jw", "dianzi",
    "bigdata", "data", "cloud", "python", "test", "dev", "git", "web",
]


# ============ 被动收集：证书透明度 ============
def crt_sh_subdomains(domain, timeout=20):
    """通过 crt.sh 证书透明度查询子域名（纯被动）"""
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read().decode("utf-8", errors="ignore")
            for m in re.findall(r'"name_value"\s*:\s*"([^"]+)"', data):
                for name in m.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith("." + domain) and name.count(".") <= 4:
                        subs.add(name)
    except Exception:
        pass
    return subs


# ============ 主动收集：DNS子域暴力枚举 ============
def _resolve(host, timeout=3):
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def dns_brute_subdomains(domain):
    """DNS暴力枚举已知子域前缀（低强度）"""
    found = []
    def _work(prefix):
        host = f"{prefix}.{domain}"
        if _resolve(host):
            found.append(host)
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(_work, EduSubPrefixes))
    return found


# ============ 外部工具封装 ============
def run_tool(cmd, timeout=300):
    """调用外部工具，返回stdout文本"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def external_subfinder(domain):
    if which("subfinder"):
        out = run_tool(["subfinder", "-d", domain, "-silent"])
        return [l.strip() for l in out.splitlines() if l.strip()]
    return []


# ============ 主流程 ============
def collect_assets(school, use_external=True, stop_flag=None, emit=None):
    """对一所学校执行完整资产收集，返回 sorted 子域名列表。

    stop_flag: threading.Event，置位时尽早退出
    emit: 回调函数 emit(msg)，用于GUI进度显示；None则用print
    """
    def _out(msg):
        if emit:
            emit(msg)
        else:
            print(msg)

    _out(f"[*] 开始收集: {school['name']} ({school['domains'][0]})")
    out_dir = output_dir_for(school["code"])
    subdomains = set()

    for domain in school["domains"]:
        if stop_flag and stop_flag.is_set():
            _out("[!] 已停止")
            break
        subdomains.add(domain)  # 主域名
        _out(f"    被动收集子域: {domain}")
        # 1. 外部 subfinder（可选）
        if use_external and not (stop_flag and stop_flag.is_set()):
            subs = external_subfinder(domain)
            if subs:
                subdomains.update(subs)
                _out(f"      subfinder: +{len(subs)}")
            else:
                _out("      subfinder 不可用，降级纯Python")
        # 2. crt.sh 被动
        subs = crt_sh_subdomains(domain)
        subdomains.update(subs)
        _out(f"      crt.sh: +{len(subs)}")
        # 3. DNS 前缀暴力（主动，低强度）
        subs = dns_brute_subdomains(domain)
        subdomains.update(subs)
        _out(f"      DNS探测: +{len(subs)}")

    # 保存子域清单
    subs_path = out_dir / "subdomains.txt"
    with open(subs_path, "w", encoding="utf-8") as f:
        for s in sorted(subdomains):
            f.write(s + "\n")
    _out(f"    ✓ 子域清单已保存: {subs_path} (共 {len(subdomains)} 条)")
    return sorted(subdomains)


if __name__ == "__main__":
    import sys as _s
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from data.universities import get
    code = _s.argv[1] if len(_s.argv) > 1 else "zju"
    school = get(code) or {"name": code, "code": code, "domains": [code + ".edu.cn"]}
    subdomains = collect_assets(school)
    print("\n示例结果：")
    for s in subdomains[:20]:
        print("  ", s)