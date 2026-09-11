# -*- coding: utf-8 -*-
"""资产探活与Web指纹识别"""

import sys
import ssl
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import which, output_dir_for

FAVICON_HASHES = {}

def _fetch(url, timeout=8):
    """发起HTTP请求，返回(status, headers_dict, body)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            headers = dict(r.headers.items())
            body = r.read(200000)  # 只读前200KB
            return r.status, headers, body
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers.items()), b""
        except Exception:
            return e.code, {}, b""
    except Exception:
        return None, {}, b""


# ============ 指纹规则：基于响应头 + 标题 + 特征串 ============
def fingerprint(status, headers, body, url):
    """识别目标技术栈，返回softwares空白字典与特征"""
    text = ""
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        pass
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    tech = []
    # Server 头
    server = headers_lower.get("server", "")
    srv = server.split("/")[0] if server else ""
    if srv:
        tech.append(("Server", server))
    # 生成框架
    if "x-powered-by" in headers_lower:
        tech.append(("X-Powered-By", headers_lower["x-powered-by"]))
    # 常见CMS/框架特征
    lower_text = text.lower()
    checks = {
        "Apache": "apache" in server,
        "Nginx": "nginx" in server,
        "IIS": "microsoft-iis" in server,
        "Spring": "spring" in headers_lower.get("x-application-context", "") or "spring" in lower_text,
        "ThinkPHP": "thinkphp" in lower_text,
        "Laravel": "laravel" in headers_lower.get("x-powered-by", ""),
        "Django": "django" in headers_lower.get("server", "") or "csrftoken" in text,
        "WordPress": "wp-content" in lower_text or "wordpress" in lower_text,
        "Discuz/Q3Cms": "discuz" in lower_text,
        "DedeCMS": "dedecms" in lower_text,
        "教育OA/泛微": "weaver" in lower_text or "ecology" in lower_text,
        "致远OA": "seeyon" in lower_text,
        "Shiro": "rememberme=deleteme" in headers_lower.get("set-cookie", ""),
        "Fastjson": "fastjson" in lower_text,
        "Shiro500": "404" in lower_text,  # 占位，不再误判
    }
    found = []
    for name, hit in checks.items():
        if hit:
            found.append(name)

    # 标题
    title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = title_m.group(1).strip()[:80] if title_m else ""

    return {
        "url": url,
        "status": status,
        "title": title,
        "tech": [t for t in tech],
        "hits": found,
        "server": srv,
    }


# ============ 主流程 ============
def probe_assets(subdomains, school_code, concurrency=30, stop_flag=None, emit=None):
    """对子域名做HTTP探活+指纹"""
    def _out(msg):
        if emit:
            emit(msg)
        else:
            print(msg)

    _out(f"[*] 探活与指纹识别: {len(subdomains)} 个域名")
    out_dir = output_dir_for(school_code)
    results = []

    targets = []
    for d in subdomains:
        if stop_flag and stop_flag.is_set():
            break
        targets.append(("http://" + d, d))
        # 不强制HTTPS，避免误报；各域名默认探测http，列出时同步标注

    def _probe(item):
        if stop_flag and stop_flag.is_set():
            return None
        url, domain = item
        try:
            status, headers, body = _fetch(url)
            if status is None:
                return None
            fp = fingerprint(status, headers, body, url)
            fp["domain"] = domain
            return fp
        except Exception:
            return None

    alive = []
    done = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for fp in pool.map(_probe, targets):
            done += 1
            if stop_flag and stop_flag.is_set():
                break
            if fp and fp["status"]:
                results.append(fp)
                alive.append(fp)
            if emit and done % 20 == 0:
                emit(f"      探活进度: {done}/{len(targets)}, 存活 {len(alive)}")

    # 结果排序（按域名）
    results.sort(key=lambda x: x["domain"])

    # 保存探活结果
    alive_path = out_dir / "alive_urls.txt"
    with open(alive_path, "w", encoding="utf-8") as f:
        for fp in alive:
            f.write(f"{fp['url']}\t{fp['status']}\t{fp['title']}\t{fp['server']}\n")
    _out(f"    ✓ 存活资产已保存: {alive_path} (共 {len(alive)} 个存活)")
    return results


if __name__ == "__main__":
    import sys as _s
    subdomains = []
    p = Path("outputs/zju/subdomains.txt")
    if p.exists():
        subdomains = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    res = probe_assets(subdomains, "zju")
    for fp in res[:30]:
        print(fp["url"], fp["status"], fp["title"], fp["server"], fp["hits"])