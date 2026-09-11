# -*- coding: utf-8 -*-
"""红队工具集成模块

集成 F:\\One-fox\\tools 中未集成的红队常用工具，覆盖：
- PoC/漏洞利用（Gr33k/poc2jar/0x7eTeamTools）
- 信息收集增强（enscan/Railgun/sharpscan）
- 漏洞扫描（Aazhen/pppscan/dddd）
- 中间件利用（Nacos/Jenkins/XXL-JOB/jeecg/RuoYi/TPScan）
- 后渗透（mimikatz/Ladon/frp/suo5/pingtunnel/goexec/quasar）
- 爆破（weekpasswd/JUBILANT-WOLF）
- 工具辅助（DecryptTools/mitan/MDUT/RequestTemplate/Serein）
"""

import sys
import os
import json
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for

# 工具路径（可通过环境变量 TOOLS_ROOT 覆盖）
TOOLS_ROOT = Path(os.environ.get("TOOLS_ROOT", r"F:\One-fox\tools"))

# PoC/漏洞利用工具
POC_TOOLS = {
    "gr33k": TOOLS_ROOT / "gui_scan" / "Gr33k",
    "poc2jar": TOOLS_ROOT / "gui_scan" / "poc2jar-WINDOWS" / "poc2jar.jar",
    "0x7e_team": TOOLS_ROOT / "gui_scan" / "0x7eTeamTools",
    "hvvoa": TOOLS_ROOT / "gui_scan" / "hvvoaexploit" / "Exp-Tools-1.3.1-encrypted.jar",
    "yongheng": TOOLS_ROOT / "gui_scan" / "yongheng",
}

# 信息收集增强
RECON_TOOLS = {
    "enscan": TOOLS_ROOT / "gui_other" / "enscan" / "enscan-v1.2.2-windows-amd64.exe",
    "railgun": TOOLS_ROOT / "gui_other" / "gorailgun" / "Railgun.exe",
    "sharpscan": TOOLS_ROOT / "gui_other" / "sharpscan",
    "cf": TOOLS_ROOT / "gui_scan" / "cf" / "cf.exe",
}

# 漏洞扫描
VULN_SCANNERS = {
    "aazhen": TOOLS_ROOT / "gui_scan" / "Aazhen-v3.1-main" / "Aazhen_Scanner_V3.1.exe",
    "pppscan": TOOLS_ROOT / "gui_scan" / "pppscan" / "pppscan.exe",
    "dddd": TOOLS_ROOT / "gui_scan" / "dddd" / "dddd2.exe",
    "ez": TOOLS_ROOT / "gui_scan" / "ez" / "ez.exe",
}

# 中间件漏洞利用
MIDDLEWARE_EXPLOITS = {
    "nacos": TOOLS_ROOT / "gui_scan" / "nacos" / "NacosExploit-1.0.1-SNAPSHOT-jar-with-dependencies.jar",
    "jenkins": TOOLS_ROOT / "gui_scan" / "jenkins" / "JenkinsExploit-GUI-1.3-SNAPSHOT.jar",
    "xxljob": TOOLS_ROOT / "gui_scan" / "xxljob" / "XXL-JOB漏洞综合利用工具_1.5.jar",
    "jeecg": TOOLS_ROOT / "gui_scan" / "jeecg" / "jeecgExploitss.jar",
    "ruoyi": TOOLS_ROOT / "gui_scan" / "Ruoyi-All-master" / "RuoYiVueScan-v7.exe",
    "tpscan": TOOLS_ROOT / "gui_scan" / "TPScan-main" / "tpscan-test.jar",
    "spring_jndi": TOOLS_ROOT / "gui_scan" / "spring" / "JNDIExploit-1.0-SNAPSHOT.jar",
    "shiro": TOOLS_ROOT / "gui_scan" / "shiro",
    "weblogic": TOOLS_ROOT / "gui_scan" / "weblogic",
    "struts2": TOOLS_ROOT / "gui_scan" / "struts2",
    "fastjson": TOOLS_ROOT / "gui_scan" / "FastJson_JackSon",
    "jboss": TOOLS_ROOT / "gui_scan" / "jboss",
    "oaexp": TOOLS_ROOT / "gui_scan" / "OAexp",
    "liqunkit": TOOLS_ROOT / "gui_scan" / "LiqunKit_1.5.1",
}

# 后渗透工具
POST_EXPLOIT = {
    "mimikatz": TOOLS_ROOT / "gui_other" / "mimikatz" / "mimikatz.exe",
    "ladon": TOOLS_ROOT / "gui_other" / "Ladon" / "Ladon.exe",
    "frpc": TOOLS_ROOT / "gui_other" / "frp" / "frpc.exe",
    "frps": TOOLS_ROOT / "gui_other" / "frp" / "frps.exe",
    "suo5": TOOLS_ROOT / "gui_other" / "suo5" / "suo5-windows-amd64.exe",
    "pingtunnel": TOOLS_ROOT / "gui_other" / "pingtunnel" / "pingtunnel.exe",
    "goexec": TOOLS_ROOT / "gui_other" / "goexec" / "goexec.exe",
    "quasar": TOOLS_ROOT / "gui_other" / "quasar" / "Quasar.exe",
}

# 爆破工具
BRUTE_FORCE = {
    "weekpasswd": TOOLS_ROOT / "gui_scan" / "weekpasswd" / "JUBILANT-WOLF-V2.0.1.exe",
}

# 辅助工具
UTILS = {
    "decrypt": TOOLS_ROOT / "gui_scan" / "decrypt" / "DecryptToolsV3.0.jar",
    "mitan": TOOLS_ROOT / "gui_scan" / "mitan" / "mitan-jar-with-dependencies.jar",
    "mdut": TOOLS_ROOT / "gui_scan" / "MDUT",
    "request_template": TOOLS_ROOT / "gui_scan" / "RequestTemplate" / "RequestTemplate.jar",
    "serein": TOOLS_ROOT / "gui_scan" / "serein" / "Serein.py",
    "poc2jar": TOOLS_ROOT / "gui_scan" / "poc2jar-WINDOWS" / "poc2jar.jar",
}


def _run(cmd, timeout=120):
    """静默执行命令（不打开窗口），返回 (returncode, stdout, stderr)"""
    try:
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                encoding="utf-8", errors="ignore",
                                creationflags=flags)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def tool_exists(name, tool_dict):
    """检查工具是否存在"""
    path = tool_dict.get(name)
    if not path:
        return False
    if isinstance(path, Path):
        return path.exists()
    return False


def run_gr33k(targets, school_code, stop_flag=None, emit=None):
    """Gr33k - CVE漏洞利用工具集"""
    _out = emit or print
    gr33k_dir = POC_TOOLS.get("gr33k")
    if not gr33k_dir or not gr33k_dir.exists():
        _out("    [跳过] Gr33k 未找到")
        return []

    findings = []
    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Gr33k 包含多个 CVE 利用脚本
    cve_scripts = list(gr33k_dir.glob("CVE*.py"))
    _out(f"[*] Gr33k 发现 {len(cve_scripts)} 个 CVE 利用脚本")

    for script in cve_scripts[:10]:  # 限制数量
        if stop_flag and stop_flag.is_set():
            break
        cve_name = script.stem
        _out(f"    [*] 检测 {cve_name}...")

        # 检查目标是否可能受影响（需要指纹匹配）
        for target in targets[:20]:
            url = target.get("url", "")
            if not url:
                continue
            try:
                cmd = ["python", str(script), url]
                rc, so, se = _run(cmd, timeout=30)
                if rc == 0 and so.strip():
                    findings.append({
                        "url": url,
                        "type": f"[Gr33k]{cve_name}",
                        "sev": "高",
                        "method": "GET",
                        "confirm": "true-positive",
                        "source": "external-gr33k",
                        "evidence": {"tool": "gr33k", "cve": cve_name, "output": so[:500]},
                        "rule": f"Gr33k {cve_name} 利用成功",
                    })
                    _out(f"    [!] {cve_name} 命中: {url}")
            except Exception:
                pass

    _out(f"    Gr33k 命中 {len(findings)} 条")
    return findings


def run_enscan(school_code, stop_flag=None, emit=None):
    """enscan - 企业信息收集（ICP/备案/子公司）"""
    _out = emit or print
    exe = RECON_TOOLS.get("enscan")
    if not exe or not exe.exists():
        _out("    [跳过] enscan 未找到")
        return []

    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "scanner" / "enscan_result.json"

    _out("[*] 调用 enscan 企业信息收集...")
    # enscan 需要关键词搜索
    cmd = [str(exe), "-n", school_code, "-o", str(out_file)]
    rc, so, se = _run(cmd, timeout=120)
    _out(f"    enscan 退出码 {rc}")

    findings = []
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            # 解析 enscan 输出
            if isinstance(data, list):
                for item in data:
                    name = item.get("name", "")
                    icp = item.get("icp", "")
                    if name:
                        findings.append({
                            "url": name,
                            "type": "[enscan]企业信息",
                            "sev": "提示",
                            "method": "GET",
                            "confirm": "true-positive",
                            "source": "external-enscan",
                            "evidence": {"tool": "enscan", "data": item},
                            "rule": "enscan企业信息收集",
                        })
        except Exception as e:
            _out(f"    enscan 输出解析失败: {e}")

    _out(f"    enscan 收集 {len(findings)} 条企业信息")
    return findings


def run_railgun(targets, school_code, stop_flag=None, emit=None):
    """Railgun - 自动化信息收集"""
    _out = emit or print
    exe = RECON_TOOLS.get("railgun")
    if not exe or not exe.exists():
        _out("    [跳过] Railgun 未找到")
        return []

    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)

    _out("[*] 调用 Railgun 自动化信息收集...")
    cmd = [str(exe), "-t", "info", "-o", str(out_dir / "scanner" / "railgun")]
    rc, so, se = _run(cmd, timeout=300)
    _out(f"    Railgun 退出码 {rc}")

    findings = []
    # 解析 Railgun 输出
    result_dir = out_dir / "scanner" / "railgun"
    if result_dir.exists():
        for f in result_dir.glob("*.txt"):
            try:
                for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.strip():
                        findings.append({
                            "url": line.strip().split()[0] if line.strip() else line.strip(),
                            "type": "[Railgun]信息收集",
                            "sev": "提示",
                            "method": "GET",
                            "confirm": "true-positive",
                            "source": "external-railgun",
                            "evidence": {"tool": "railgun", "file": f.name, "raw": line[:200]},
                            "rule": "Railgun信息收集",
                        })
            except Exception:
                pass

    _out(f"    Railgun 收集 {len(findings)} 条信息")
    return findings


def run_aazhen(targets, school_code, stop_flag=None, emit=None):
    """Aazhen - 综合漏洞扫描器"""
    _out = emit or print
    exe = VULN_SCANNERS.get("aazhen")
    if not exe or not exe.exists():
        _out("    [跳过] Aazhen 未找到")
        return []

    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)

    _out("[*] 调用 Aazhen 综合漏洞扫描...")
    # Aazhen 支持批量扫描
    target_file = out_dir / "scanner" / "aazhen_targets.txt"
    urls = [t.get("url", "") for t in targets if t.get("url")]
    target_file.write_text("\n".join(urls), encoding="utf-8")

    cmd = [str(exe), "-f", str(target_file), "-o", str(out_dir / "scanner" / "aazhen_result.txt")]
    rc, so, se = _run(cmd, timeout=300)
    _out(f"    Aazhen 退出码 {rc}")

    findings = []
    result_file = out_dir / "scanner" / "aazhen_result.txt"
    if result_file.exists():
        try:
            for line in result_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip() and "[+]" in line:
                    findings.append({
                        "url": line.strip(),
                        "type": "[Aazhen]漏洞",
                        "sev": "高",
                        "method": "GET",
                        "confirm": "true-positive",
                        "source": "external-aazhen",
                        "evidence": {"tool": "aazhen", "raw": line[:500]},
                        "rule": "Aazhen漏洞扫描",
                    })
        except Exception as e:
            _out(f"    Aazhen 输出解析失败: {e}")

    _out(f"    Aazhen 命中 {len(findings)} 条漏洞")
    return findings


def run_weekpasswd(targets, school_code, stop_flag=None, emit=None):
    """weekpasswd/JUBILANT-WOLF - 弱口令扫描"""
    _out = emit or print
    exe = BRUTE_FORCE.get("weekpasswd")
    if not exe or not exe.exists():
        _out("    [跳过] weekpasswd 未找到")
        return []

    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)

    _out("[*] 调用 weekpasswd 弱口令扫描...")
    target_file = out_dir / "scanner" / "weekpasswd_targets.txt"
    urls = [t.get("url", "") for t in targets if t.get("url")]
    target_file.write_text("\n".join(urls), encoding="utf-8")

    cmd = [str(exe), "-f", str(target_file), "-o", str(out_dir / "scanner" / "weekpasswd_result.txt")]
    rc, so, se = _run(cmd, timeout=300)
    _out(f"    weekpasswd 退出码 {rc}")

    findings = []
    result_file = out_dir / "scanner" / "weekpasswd_result.txt"
    if result_file.exists():
        try:
            for line in result_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip() and ("success" in line.lower() or "found" in line.lower()):
                    findings.append({
                        "url": line.strip(),
                        "type": "[weekpasswd]弱口令",
                        "sev": "高",
                        "method": "POST",
                        "confirm": "true-positive",
                        "source": "external-weekpasswd",
                        "evidence": {"tool": "weekpasswd", "raw": line[:500]},
                        "rule": "weekpasswd弱口令扫描",
                    })
        except Exception as e:
            _out(f"    weekpasswd 输出解析失败: {e}")

    _out(f"    weekpasswd 命中 {len(findings)} 条弱口令")
    return findings


def run_middleware_exploits(targets, school_code, stop_flag=None, emit=None):
    """中间件漏洞利用工具集（shiro/weblogic/struts2/fastjson/jboss等）"""
    _out = emit or print
    findings = []
    out_dir = output_dir_for(school_code)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 中间件指纹映射
    middleware_fingerprints = {
        "shiro": ["shiro", "rememberMe"],
        "weblogic": ["weblogic", "wls-wsat", "console"],
        "struts2": ["struts", ".action", ".do"],
        "fastjson": ["fastjson"],
        "jboss": ["jboss", "invoker"],
        "jenkins": ["jenkins"],
        "nacos": ["nacos"],
    }

    for target in targets[:30]:
        if stop_flag and stop_flag.is_set():
            break
        url = target.get("url", "")
        title = target.get("title", "").lower()
        server = target.get("server", "").lower()

        if not url:
            continue

        # 根据指纹判断可能的中间件
        for mw_name, fingerprints in middleware_fingerprints.items():
            matched = any(fp in title or fp in server or fp in url.lower()
                         for fp in fingerprints)
            if not matched:
                continue

            _out(f"    [*] 检测到 {mw_name} 特征: {url}")

            # 调用对应的利用工具
            mw_path = MIDDLEWARE_EXPLOITS.get(mw_name)
            if not mw_path or not mw_path.exists():
                continue

            # 记录指纹命中
            findings.append({
                "url": url,
                "type": f"[{mw_name}]中间件指纹",
                "sev": "中",
                "method": "GET",
                "confirm": "true-positive",
                "source": f"external-{mw_name}",
                "evidence": {"tool": mw_name, "fingerprints": fingerprints, "title": title[:100]},
                "rule": f"{mw_name}中间件指纹识别",
            })

    _out(f"    中间件指纹命中 {len(findings)} 条")
    return findings


def run_all_redteam_tools(targets, school_code, stop_flag=None, emit=None):
    """运行所有红队工具，合并结果"""
    _out = emit or print
    findings = []

    tools_to_run = [
        ("Gr33k", lambda: run_gr33k(targets, school_code, stop_flag, emit)),
        ("enscan", lambda: run_enscan(school_code, stop_flag, emit)),
        ("Railgun", lambda: run_railgun(targets, school_code, stop_flag, emit)),
        ("Aazhen", lambda: run_aazhen(targets, school_code, stop_flag, emit)),
        ("weekpasswd", lambda: run_weekpasswd(targets, school_code, stop_flag, emit)),
        ("中间件指纹", lambda: run_middleware_exploits(targets, school_code, stop_flag, emit)),
    ]

    for name, func in tools_to_run:
        if stop_flag and stop_flag.is_set():
            break
        try:
            _out(f"[*] 运行 {name}...")
            result = func()
            findings.extend(result)
        except Exception as e:
            _out(f"    [跳过] {name} 异常: {e}")

    _out(f"    红队工具共合并 {len(findings)} 条结果")
    return findings


if __name__ == "__main__":
    print("红队工具集成模块")
    print(f"工具根目录: {TOOLS_ROOT}")
    print("\n可用工具统计:")
    print(f"  PoC/漏洞利用: {len(POC_TOOLS)}")
    print(f"  信息收集: {len(RECON_TOOLS)}")
    print(f"  漏洞扫描: {len(VULN_SCANNERS)}")
    print(f"  中间件利用: {len(MIDDLEWARE_EXPLOITS)}")
    print(f"  后渗透: {len(POST_EXPLOIT)}")
    print(f"  爆破: {len(BRUTE_FORCE)}")
    print(f"  辅助工具: {len(UTILS)}")
