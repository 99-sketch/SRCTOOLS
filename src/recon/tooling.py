# -*- coding: utf-8 -*-
"""外部扫描器无缝集成（纯CLI静默执行，不打开任何窗口）

只调用纯命令行工具（nuclei/afrog/xray/fscan等），全部后台静默运行。
不打开任何GUI窗口，不弹窗，不安装。所有功能集成在exe内部。
"""

import os
import re
import sys
import json
import time
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.config import output_dir_for

# 工具根目录（可通过环境变量 TOOLS_ROOT 覆盖）
TOOLS_ROOT = Path(os.environ.get("TOOLS_ROOT", r"F:\One-fox\tools"))

# 只保留纯CLI工具（不打开任何窗口）
TOOL_PATHS = {
    # 核心扫描器（纯CLI，静默运行）
    "nuclei":    r"gui_scan\nuclei\nuclei.exe",
    "afrog":     r"gui_other\afrog\afrog.exe",
    "xray":      r"gui_other\xray\xray.exe",
    "fscan":     r"gui_scan\fscan\fscan.exe",
    "ehole":     r"gui_scan\dirsearch\ehole\ehole.exe",
    "P1finger":  r"gui_scan\P1finger\P1finger64.exe",
    "httpx":     r"gui_scan\fcke\httpx.exe",
    "sqlmap":    r"gui_scan\sqlmap-master\sqlmap.py",
    "tscanplus": r"gui_scan\tscanplus\TscanPlus_Win_Amd64.exe",
    "kscan":     r"gui_other\kscan\kscan_windows_amd64.exe",
    "massdns":   r"gui_shouji\oneforall\thirdparty\massdns\windows\x64\massdns.exe",
    "oneforall": r"gui_shouji\oneforall\oneforall.py",
    "webcrack":  r"gui_scan\WebCrack-master\2024-03-14-0.1.2-win-x64.exe",
    "aazhen":    r"gui_scan\Aazhen-v3.1-main\Aazhen_Scanner_V3.1.exe",
    "weekpasswd": r"gui_scan\weekpasswd\JUBILANT-WOLF-V2.0.1.exe",
    "ruoyi_scan": r"gui_scan\Ruoyi-All-master\ruoyitools\RuoYiVueScan-v7.exe",
}


def tool_path(name):
    """获取工具路径（静默，不报错）"""
    if not TOOLS_ROOT.exists():
        return None
    p = TOOLS_ROOT / TOOL_PATHS.get(name, "")
    return str(p) if p.exists() else None


def _run(cmd, timeout=300, cwd=None):
    """静默运行外部命令（不打开窗口）"""
    try:
        # CREATE_NO_WINDOW = 不创建控制台窗口
        # CREATE_NEW_PROCESS_GROUP = 新进程组，避免继承父进程窗口
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd or str(Path(__file__).resolve().parent.parent.parent),
            creationflags=flags,
            startupinfo=subprocess.STARTUPINFO() if sys.platform == "win32" else None,
        )
        if sys.platform == "win32" and proc.startupinfo:
            proc.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc.startupinfo.wShowWindow = 0  # SW_HIDE
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _write_targets(alive_results, school_code):
    """把存活资产写入该校输出目录的 urls.txt"""
    out_dir = output_dir_for(school_code)
    urls = sorted({a["url"] for a in alive_results})
    p = out_dir / "scanner" / "targets.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return p, urls


# ================= nuclei =================
_NUCLEI_IGNORE_INFO = {"client-side-detection", "exposure", "miscellaneous"}
_NUCLEI_SEV_MAP = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}


def run_nuclei(alive_results, school_code, stop_flag=None, emit=None):
    """nuclei 模板扫描（静默CLI）"""
    if stop_flag and stop_flag.is_set():
        return []
    _out = emit or print
    exe = tool_path("nuclei")
    if not exe:
        return []
    targets, urls = _write_targets(alive_results, school_code)
    out_dir = output_dir_for(school_code)
    out_json = out_dir / "scanner" / "nuclei.jsonl"
    _out("[*] nuclei 扫描...")
    cmd = [exe, "-l", str(targets), "-jsonl", "-o", str(out_json),
           "-silent", "-no-color", "-system-resolvers"]
    for tag in _NUCLEI_IGNORE_INFO:
        cmd.extend(["-tags", f"-{tag}"])
    rc, so, se = _run(cmd, timeout=600)
    _out(f"    nuclei 退出码 {rc}")
    if not out_json.exists():
        return []
    findings = []
    try:
        for line in out_json.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", d)
            sev = _NUCLEI_SEV_MAP.get(str(info.get("severity", "low")).lower(), "中")
            findings.append({
                "url": d.get("matched-at", d.get("host", d.get("url", ""))),
                "type": f"[nuclei]{info.get('name', d.get('template-id', '未命名'))}",
                "sev": sev, "method": "GET/POST",
                "confirm": "true-positive", "source": "external-nuclei",
                "evidence": {
                    "tool": "nuclei",
                    "name": info.get("name", ""),
                    "severity": info.get("severity", ""),
                    "snippet": (d.get("matched") or d.get("output") or str(d))[:400],
                    "verification": f"nuclei模板「{info.get('name','')}」命中",
                },
                "rule": f"nuclei模板命中 {info.get('name','')}",
            })
    except Exception as jerr:
        _out(f"    nuclei 输出解析失败: {jerr}")
    _out(f"    nuclei 命中 {len(findings)} 条")
    return findings


# ================= afrog =================
def _run_afrog(alive_results, school_code, stop_flag=None, emit=None):
    """afrog 漏洞扫描（静默CLI）"""
    _out = emit or print
    findings = []
    try:
        exe = tool_path("afrog")
        if not exe:
            return findings
        _out("[*] afrog 扫描...")
        targets, _ = _write_targets(alive_results, school_code)
        out_json_path = output_dir_for(school_code) / "scanner" / "afrog.json"
        rc, so, se = _run([exe, "-T", str(targets), "-o", str(out_json_path),
                           "-S", "medium,high,critical", "-silent"], timeout=420)
        _out(f"    afrog 退出码 {rc}")
        if out_json_path.exists():
            try:
                arr = json.loads(out_json_path.read_text(encoding="utf-8", errors="ignore"))
                for d in (arr if isinstance(arr, list) else []):
                    if not isinstance(d, dict):
                        continue
                    info = d.get("info", d)
                    sev = _NUCLEI_SEV_MAP.get(str(info.get("severity", "low")).lower(), "中")
                    findings.append({
                        "url": d.get("target", d.get("url", "")),
                        "type": f"[afrog]{info.get('name', d.get('name', '未命名'))}",
                        "sev": sev, "method": "GET/POST",
                        "confirm": "true-positive", "source": "external-afrog",
                        "evidence": {
                            "tool": "afrog",
                            "name": info.get("name", ""),
                            "severity": info.get("severity", ""),
                            "snippet": (d.get("output") or d.get("result") or str(d))[:400],
                            "verification": f"afrog PoC「{info.get('name','')}」命中 {d.get('target','')}",
                        },
                        "rule": f"afrog漏洞扫描命中 {info.get('name','')}",
                    })
            except Exception as jerr:
                _out(f"    afrog 输出解析失败: {jerr}")
        _out(f"    afrog 命中 {len(findings)} 条")
    except Exception as e:
        _out(f"    [跳过] afrog 异常: {e}")
    return findings


# ================= xray =================
def run_xray(alive_results, school_code, stop_flag=None, emit=None):
    """xray 综合漏洞扫描（静默CLI）"""
    _out = emit or print
    exe = tool_path("xray")
    if not exe:
        return []
    targets, urls = _write_targets(alive_results, school_code)
    out_dir = output_dir_for(school_code)
    out_json = out_dir / "scanner" / "xray_webscan.json"
    _out("[*] xray 综合扫描...")
    cmd = [exe, "webscan", "--url-file", str(targets),
           "--json-output", str(out_json),
           "--timeout", "30", "--cookie", "*"]
    rc, so, se = _run(cmd, timeout=540)
    _out(f"    xray 退出码 {rc}")
    if not out_json.exists():
        return []
    findings = []
    try:
        arr = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
    except Exception as jerr:
        _out(f"    xray 输出解析失败: {jerr}")
        return []
    _SEV = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "提示"}
    for d in (arr if isinstance(arr, list) else []):
        if not isinstance(d, dict):
            continue
        vuln = d.get("vuln_class", d.get("plugin", ""))
        sev = _SEV.get(str(d.get("severity", "medium")).lower(), "中")
        findings.append({
            "url": d.get("target", d.get("detail", {}).get("addr", "")),
            "type": f"[xray]{vuln or '未知'}",
            "sev": sev, "method": d.get("method", "GET"),
            "confirm": "true-positive", "source": "external-xray",
            "evidence": {
                "tool": "xray",
                "vuln_class": vuln,
                "snippet": json.dumps(d, ensure_ascii=False)[:400],
                "verification": f"xray检测到 {vuln}",
            },
            "rule": f"xray命中 {vuln}",
        })
    _out(f"    xray 命中 {len(findings)} 条")
    return findings


# ================= ehole 指纹 =================
def run_fingerprint(alive_results, school_code, emit=None):
    """ehole 指纹识别（静默CLI）"""
    _out = emit or print
    exe = tool_path("ehole") or tool_path("P1finger")
    if not exe:
        return []
    out_dir = output_dir_for(school_code)
    targets, urls = _write_targets(alive_results, school_code)
    out_txt = out_dir / "scanner" / "ehole_finger.txt"
    rc, so, se = _run([exe, "finger", "-l", str(targets), "-o", str(out_txt)], timeout=180)
    _out(f"    ehole 指纹识别退出码 {rc}")
    result = {}
    if out_txt.exists():
        for line in out_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if "://" in line or "\t" in line or "," in line:
                m = re.split(r"[\t,]", line, maxsplit=1)
                if len(m) == 2:
                    result[m[0].strip()] = re.split(r"[;|,]", m[1].strip())
    return result


# ================= Python原生指纹检测（不依赖外部工具）=================
def native_fingerprint(url, timeout=10):
    """Python原生指纹检测（静默，不打开任何窗口）"""
    import requests
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        text = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        tags = []
        
        # 常见中间件指纹
        fingerprints = {
            "shiro": ["shiro", "rememberMe=deleteMe"],
            "fastjson": ["fastjson", "com.sun.rowset"],
            "log4j2": ["log4j", "jndi"],
            "struts2": ["struts", ".action", "struts2"],
            "weblogic": ["weblogic", "wls-wsat", "console"],
            "spring": ["spring", "whitelabel error"],
            "thinkphp": ["thinkphp", "thinkphp_trace"],
            "nacos": ["nacos", "alibaba"],
            "jenkins": ["jenkins"],
            "tomcat": ["tomcat"],
            "nginx": ["nginx"],
            "apache": ["apache"],
            "iis": ["iis", "microsoft"],
            "php": ["php", "x-powered-by"],
            "asp": ["asp", "x-aspnet"],
            "java": ["java", "jsp"],
        }
        
        for name, keywords in fingerprints.items():
            for kw in keywords:
                if kw in text or kw in str(headers):
                    tags.append(name)
                    break
        
        return {"url": url, "tags": list(set(tags)), "status": resp.status_code}
    except Exception:
        return {"url": url, "tags": [], "status": 0}


# ================= Python原生敏感文件检测 =================
SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/WEB-INF/web.xml",
    "/application.yml",
    "/application.properties",
    "/config.yml",
    "/settings.py",
    "/.env",
    "/.DS_Store",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/api-docs",
    "/druid/index.html",
    "/heapdump",
    "/actuator/heapdump",
]


def native_sensitive_scan(url, timeout=10):
    """Python原生敏感文件检测（静默）"""
    import requests
    findings = []
    try:
        for path in SENSITIVE_PATHS:
            try:
                target = url.rstrip("/") + path
                resp = requests.get(target, timeout=timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 10:
                    findings.append({
                        "url": target,
                        "type": f"[敏感文件]{path}",
                        "sev": "高" if "config" in path or ".env" in path else "中",
                        "method": "GET",
                        "confirm": "true-positive",
                        "source": "native-sensitive-scan",
                        "evidence": {
                            "tool": "native",
                            "path": path,
                            "size": len(resp.content),
                            "verification": f"敏感文件 {path} 可访问(HTTP 200)",
                        },
                        "rule": f"敏感文件探测: {path}",
                    })
            except Exception:
                continue
    except Exception:
        pass
    return findings


# ================= 总入口（并行执行）=================
def run_external_scanners(alive_results, school_code, do_finger=True,
                          stop_flag=None, emit=None):
    """并行调用CLI扫描器 + Python原生检测，全部静默后台运行。"""
    _out = emit or print
    findings = []

    # 指纹先跑
    if do_finger:
        try:
            run_fingerprint(alive_results, school_code, emit=emit)
        except Exception as e:
            _out(f"    [跳过] 指纹识别异常: {e}")

    # 定义所有扫描任务
    scan_tasks = [
        ("nuclei", lambda: run_nuclei(alive_results, school_code, stop_flag, emit=emit)),
        ("afrog", lambda: _run_afrog(alive_results, school_code, stop_flag, emit=emit)),
        ("xray", lambda: run_xray(alive_results, school_code, stop_flag, emit=emit)),
        ("native_fingerprint", lambda: _run_native_fingerprint(alive_results, school_code, stop_flag, emit=emit)),
        ("native_sensitive", lambda: _run_native_sensitive(alive_results, school_code, stop_flag, emit=emit)),
    ]

    # 并行执行
    _out("[*] 并行启动扫描器（全部静默后台运行）...")
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_name = {executor.submit(func): name for name, func in scan_tasks}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            if stop_flag and stop_flag.is_set():
                continue
            try:
                result = future.result(timeout=600)
                findings.extend(result)
                _out(f"    ✓ {name} 完成，发现 {len(result)} 条")
            except Exception as e:
                pass  # 静默跳过

    _out(f"    扫描器共合并 {len(findings)} 条证据漏洞")
    return findings


def _run_native_fingerprint(alive_results, school_code, stop_flag=None, emit=None):
    """Python原生指纹检测（并行）"""
    findings = []
    for target in alive_results[:20]:
        if stop_flag and stop_flag.is_set():
            break
        url = target.get("url", "")
        if not url:
            continue
        result = native_fingerprint(url)
        for tag in result.get("tags", []):
            findings.append({
                "url": url,
                "type": f"[指纹]{tag}",
                "sev": "提示",
                "method": "GET",
                "confirm": "true-positive",
                "source": "native-fingerprint",
                "evidence": {"tool": "native", "tag": tag},
                "rule": f"Python原生指纹检测: {tag}",
            })
    return findings


def _run_native_sensitive(alive_results, school_code, stop_flag=None, emit=None):
    """Python原生敏感文件检测（并行）"""
    findings = []
    for target in alive_results[:10]:
        if stop_flag and stop_flag.is_set():
            break
        url = target.get("url", "")
        if not url:
            continue
        findings.extend(native_sensitive_scan(url))
    return findings
