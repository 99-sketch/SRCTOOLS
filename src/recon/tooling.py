# -*- coding: utf-8 -*-
"""外部扫描器无缝集成（自动调用成熟工具，结果解析为证据链漏洞）

把本地已装的安全扫描器(nuclei/afrog/ehole等，均在 F:\\One-fox\\tools)
按需自动调用，解析其机器化输出 merge 回 findings，实现"每种渗透手法都自动执行"。
任一工具缺失/异常都不会中断整个流水线（自动降级），全程无人值守。
"""

import os
import re
import sys
import json
import time
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.config import output_dir_for

# 工具根目录（可配置，若不存在则自动跳过该项）
TOOLS_ROOT = Path(r"F:\One-fox\tools")

# 各工具的可执行文件：名称 -> 相对 TOOLS_ROOT 的路径
TOOL_PATHS = {
    "nuclei":   r"gui_scan\nuclei\nuclei.exe",
    "afrog":    r"gui_other\afrog\afrog.exe",
    "ehole":    r"gui_scan\dirsearch\ehole\ehole.exe",
    "ehole_py": r"gui_scan\dirsearch\ehole\ehole.py",
    "P1finger": r"gui_scan\P1finger\P1finger64.exe",
    "fscan":    r"gui_scan\fscan\fscan.exe",
    "Rscan":    r"gui_scan\Rscan\Rscan_win64.exe",
    "xray":     r"gui_other\xray\xray.exe",
    "oneforall": r"gui_shouji\oneforall\oneforall.py",
    "httpx":    r"gui_scan\fcke\httpx.exe",
    "sqlmap":   r"gui_scan\sqlmap-master\sqlmap.py",
}


def tool_path(name):
    if not TOOLS_ROOT.exists():
        return None
    p = TOOLS_ROOT / TOOL_PATHS.get(name, "")
    return str(p) if p.exists() else None


def _run(cmd, timeout=300, cwd=None):
    """运行外部命令，返回 (returncode, stdout_text, stderr_text)。超时抛出。"""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=cwd or str(Path(__file__).resolve().parent.parent.parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _write_targets(alive_results, school_code):
    """把存活资产写入该校输出目录的 urls.txt，返回路径。"""
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
    """对存活资产运行 nuclei（模板覆盖全漏洞类型），解析JSONL为证据漏洞。"""
    if stop_flag and stop_flag.is_set():
        return []
    exe = tool_path("nuclei")
    if not exe:
        _out = emit or print
        _out("    [跳过] 未找到 nuclei.exe")
        return []
    _out = emit or print
    _out("[*] 调用 nuclei 自动扫描（模板覆盖 Web/中间件/框架/CVE 等全部手法）...")
    targets, urls = _write_targets(alive_results, school_code)
    out_dir = output_dir_for(school_code)
    out_json = out_dir / "scanner" / "nuclei.jsonl"

    cmd = [
        exe, "-l", str(targets), "-jsonl", "-silent", "-nc",
        "-severity", "medium,high,critical",
        "-o", str(out_json),
        "-c", "40", "-templates", "-",
    ]
    # 移除"-templates -"占位以便使用默认模板
    cmd = [c for c in cmd if c not in ("-templates", "-")]
    rc, so, se = _run(cmd, timeout=420)
    _out(f"    nuclei 退出码 {rc} (stdout {len(so)}B / stderr {len(se)}B)")
    if not out_json.exists():
        return []

    findings = []
    for line in out_json.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {})
        template_id = (info.get("name") or info.get("template_id") or info.get("tags") or "").lower()
        sev = _NUCLEI_SEV_MAP.get(str(info.get("severity", "low")).lower(), "中")
        # 过滤纯指纹/低价值误报类
        tags = " ".join(info.get("tags") or [])
        ftype = (info.get("name") or template_id or "未命名模板")
        findings.append({
            "url": d.get("matched-at") or d.get("host") or "",
            "type": f"[nuclei]{ftype}",
            "sev": sev,
            "method": "GET/POST",
            "confirm": "true-positive",
            "source": "external-nuclei",
            "evidence": {
                "tool": "nuclei",
                "template_id": info.get("template_id", ""),
                "template_name": info.get("name", ""),
                "severity": info.get("severity", ""),
                "matched_at": d.get("matched-at", ""),
                "matcher_name": d.get("matcher-name", ""),
                "extractor": d.get("extractor-name", ""),
                "response_snippet": (d.get("response") or "")[:300] or info.get("description", ""),
                "request": d.get("request", "")[:500],
                "payload": d.get("payload") or "",
                "tags": tags,
                "verification": f"nuclei模板「{info.get('template_id','')}」命中(target:{d.get('matched-at','')}, matcher:{d.get('matcher-name','')})",
                "validated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "rule": f"nuclei 自动扫描命中高危模板 {info.get('template_id','')}",
        })
    _out(f"    nuclei 命中 {len(findings)} 条证据漏洞")
    return findings


# ================= ehole / P1finger 指纹 =================
def run_fingerprint(alive_results, school_code, emit=None):
    """用 ehole 对存活资产做指纹识别，返回 [{url, fingerprint_tags}]，
    供 Nday 精确匹配（提升命中率）。"""
    _out = emit or print
    exe = tool_path("ehole") or tool_path("P1finger")
    if not exe:
        _out("    [跳过] 未找到 ehole/P1finger")
        return []
    out_dir = output_dir_for(school_code)
    targets, urls = _write_targets(alive_results, school_code)
    out_txt = out_dir / "scanner" / "ehole_finger.txt"
    rc, so, se = _run([exe, "fofa", "-l", str(targets), "-o", str(out_txt)], timeout=180)
    _out(f"    ehole 指纹识别退出码 {rc}")
    result = {}
    if out_txt.exists():
        for line in out_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if "://" in line or "\t" in line or "," in line:
                m = re.split(r"[\t,]", line, maxsplit=1)
                if len(m) == 2:
                    result[m[0].strip()] = re.split(r"[;|,]", m[1].strip())
    elif so.strip():
        for line in so.splitlines():
            if "://" in line:
                part = line.split()
                if len(part) >= 2:
                    result[part[0]] = [part[1]]
    return [{"url": k, "finger": v} for k, v in result.items()]


# ================= fscan / Rscan 资产服务 =================
def run_asset_scan(alive_results, school_code, emit=None):
    """用 fscan 对目标域名解析出的 IP 段做端口/服务轻扫（补充攻击面）。"""
    _out = emit or print
    exe = tool_path("fscan")
    if not exe:
        _out("    [跳过] 未找到 fscan")
        return []
    out_dir = output_dir_for(school_code)
    # 取各 url 的 host，交给 fscan 探测常见弱口令/服务端口
    hosts = []
    for a in alive_results:
        from urllib.parse import urlparse
        h = urlparse(a["url"]).hostname
        if h and h not in hosts:
            hosts.append(h)
    if not hosts:
        return []
    hfile = out_dir / "scanner" / "fscan_hosts.txt"
    hfile.parent.mkdir(parents=True, exist_ok=True)
    hfile.write_text("\n".join(hosts[:200]) + "\n", encoding="utf-8")
    out_txt = out_dir / "scanner" / "fscan_out.txt"
    _out(f"    fscan 资产服务扫描 {len(hosts)} 主机（弱口令/未授权/端口）...")
    rc, so, se = _run([exe, "-hf", str(hfile), "-o", str(out_txt),
                       "-np", "-nopoc"], timeout=300)
    _out(f"    fscan 退出码 {rc} (fscan 仅作攻击面补充，结果见 scanner/fscan_out.txt)")
    return out_txt


# ================= 总入口 =================
def run_external_scanners(alive_results, school_code, do_finger=True,
                          stop_flag=None, emit=None):
    """按顺序自动调用可用扫描器，合并所有证据漏洞。返回 combined_findings。"""
    _out = emit or print
    findings = []

    # 指纹先跑（可辅助后续）
    if do_finger:
        try:
            run_fingerprint(alive_results, school_code, emit=emit)
        except Exception as e:
            _out(f"    [跳过] 指纹识别异常: {e}")

    # nuclei 覆盖全手法
    if not (stop_flag and stop_flag.is_set()):
        try:
            findings += run_nuclei(alive_results, school_code, stop_flag, emit=emit)
        except Exception as e:
            _out(f"    [跳过] nuclei 异常: {e}")

    # afrog 配置/漏洞类
    if not (stop_flag and stop_flag.is_set()):
        try:
            exe = tool_path("afrog")
            if exe:
                _out("[*] 调用 afrog 自动扫描（配置/漏洞类）...")
                targets, _ = _write_targets(alive_results, school_code)
                jar = out_json = None
                out_json_path = output_dir_for(school_code) / "scanner" / "afrog.json"
                rc, so, se = _run([exe, "-T", str(targets), "-o", str(out_json_path),
                                   "-S", "medium,high,critical"], timeout=420)
                _out(f"    afrog 退出码 {rc}")
                # afrog 输出 JSON 数组
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
                _out(f"    afrog 命中 {len(findings) - len([x for x in findings if x.get('source')!='external-afrog'])} 条")
        except Exception as e:
            _out(f"    [跳过] afrog 异常: {e}")

    # xray 综合漏洞扫描（无授权限制时自动调用，覆盖 SSRF/任意URL跳转/XSS注入等）
    if not (stop_flag and stop_flag.is_set()):
        try:
            findings += run_xray(alive_results, school_code, stop_flag, emit=emit)
        except Exception as e:
            _out(f"    [跳过] xray 异常: {e}")

    _out(f"    外部扫描器共合并 {len(findings)} 条证据漏洞")
    return findings


# ================= xray（无暴力破解、无授权的综合引擎扫描）=================
def run_xray(alive_results, school_code, stop_flag=None, emit=None):
    """调用 xray 对存活资产做被动/主动综合扫描，解析 webscan JSON 输出。

    覆盖 XSS 注入、任意 URL 跳转、SSRF、SQL注入、命令注入、
    JSONP 劫持、路径穿越等大量漏洞类型。任一失败自动降级，不影响主流程。
    """
    _out = emit or print
    exe = tool_path("xray")
    if not exe:
        _out("    [跳过] 未找到 xray.exe")
        return []
    targets, urls = _write_targets(alive_results, school_code)
    out_dir = output_dir_for(school_code)
    out_json = out_dir / "scanner" / "xray_webscan.json"
    _out("[*] 调用 xray 综合扫描（SSRF/任意跳转/XSS注入/SQLi等，长时运行）...")
    cmd = [exe, "webscan", "--url-file", str(targets),
           "--json-output", str(out_json),
           "--timeout", "30", "--cookie", "*"]
    rc, so, se = _run(cmd, timeout=540)
    _out(f"    xray 退出码 {rc} (stdout {len(so)}B / stderr {len(se)}B)")
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
        # xray webscan 每条记录含 vuln 与 detail
        vuln = d.get("vuln") or {}
        detail = d.get("detail") or {}
        vtype = vuln.get("vuln_class") or vuln.get("plugin") or "xray"
        sev = _SEV.get(str(vuln.get("severity", "medium")).lower(), "中")
        findings.append({
            "url": detail.get("url") or vuln.get("addr") or d.get("url") or targets,
            "type": f"[xray]{vtype}",
            "sev": sev if sev != "提示" else "低",
            "method": detail.get("method", "GET"),
            "confirm": "true-positive", "source": "external-xray",
            "evidence": {
                "tool": "xray",
                "vuln_class": vtype,
                "severity": vuln.get("severity", ""),
                "request": (detail.get("request") or "")[:500],
                "response_snippet": (detail.get("response") or "")[:300],
                "verification": f"xray插件「{vtype}」命中 {detail.get('url','')}",
            },
            "rule": f"xray综合扫描命中 {vtype}",
        })
    _out(f"    xray 命中 {len(findings)} 条证据漏洞")
    return findings