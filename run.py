# -*- coding: utf-8 -*-
"""教育SRC挖洞工具 - 主入口

用法：
    python run.py                # 选校 + 全流程
    python run.py --list         # 列出全部学校
    python run.py -s zju         # 直接指定学校代码跑全流程
    python run.py -s zju --recon-only    # 只做资产收集

流程：选校 -> 资产收集 -> 探活指纹 -> 漏洞挖掘 -> 复测 -> 报告(自动缓存登记)
安全：仅做被动/低强度收集与无害探测；Nday线索仅作提示，不出具利用。
"""

import sys
import argparse
from pathlib import Path

# Windows 控制台中文显示兜底：强制还原控制台代码页 65001(UTF-8)
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 固定把项目根加入搜索路径（源码与exe(frozen)均适用）
if getattr(sys, "frozen", False):
    _RUN_ROOT = Path(sys.executable).resolve().parent
else:
    _RUN_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_RUN_ROOT))

from data.universities import UNIVERSITIES, get, search
from src.config import output_dir_for, which, LOCAL_CVE_PATHS
from src.recon.asset_collector import collect_assets
from src.recon.prober import probe_assets
from src.vuln.engine import run_vuln_engine
from src.vuln.poc_index import index_exploitarium, match_pocs
from src.reverify import reverify
from src.report.generator import build_report
from src.report.manager import default_manager


def banner():
    print("""
  ╔══════════════════════════════════════════════╗
  ║   教育SRC 挖洞自动化工具  edu-src-toolkit     ║
  ║   公益安全研究 · 授权内负责任披露             ║
  ╚══════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(description="教育SRC挖洞自动化工具")
    parser.add_argument("--list", action="store_true", help="列出全部学校")
    parser.add_argument("-s", "--school", help="指定学校代码")
    parser.add_argument("-k", "--search", help="关键词搜索学校")
    parser.add_argument("--recon-only", action="store_true", help="只做资产收集")
    parser.add_argument("--no-scan", action="store_true", help="跳过漏洞挖掘")
    parser.add_argument("--external", action="store_true", help="强制使用外部工具(需已安装)")
    parser.add_argument("--selftest", action="store_true", help="离线自检:本地库+报告生成(不联网)")
    args = parser.parse_args()

    banner()

    # ---- 离线自检：验证本地库读取 + 报告生成，全程不联网 ----
    if args.selftest:
        from src.config import BASE_DIR
        print(f"[自检] 工具根目录: {BASE_DIR}")
        # 1. 本地CVE库
        from src.vuln.engine import find_nday_for_fingerprint
        cands = find_nday_for_fingerprint(["shiro", "spring", "thinkphp"])
        print(f"[自检] 本地CNVD匹配: {len(cands)} 条Nday候选")
        # 2. PoC库
        from src.vuln.poc_index import index_exploitarium
        ps = index_exploitarium()
        print(f"[自检] 本地PoC库: {len(ps)} 个目录")
        # 3. 报告生成(用模拟数据)
        from src.report.generator import build_report
        from src.report.manager import default_manager
        fake = {"name": "自检学校", "code": "_selftest", "domains": ["selftest.edu.cn"]}
        findings = [{"url": "http://x.edu.cn/.env", "type": "环境变量泄露", "sev": "高",
                     "reverify": {"status": "confirmed", "reason": "测试"}}]
        rv = {"summary": {"confirmed": 1, "false_positive": 0, "unreachable": 0},
              "findings": findings}
        rp = build_report(fake, [], findings, cands[:5], reverify_out=rv,
                          poc_hits=ps[:2], assets_info={"assets": 0, "alive": 0})
        default_manager().register(rp, fake, {"confirmed_vulns": len(findings)})
        print(f"[自检] 报告: {rp.name} (已登记进报告缓存)")
        from src.config import LOCAL_CVE_PATHS
        print(f"[自检] 本地CVE库目录: {LOCAL_CVE_PATHS['cve_root']}")
        print("[自检] 全部通过")
        return

    if args.list:
        for u in UNIVERSITIES:
            print(f"  {u['code']:<14}  {u['name']:<16}  {u['domains'][0]}")
        return

    if args.search:
        cands = search(args.search)
        if not cands:
            print(f"! 未找到匹配 '{args.search}' 的学校")
            return
        for c in cands:
            print(f"  {c['code']:<14}  {c['name']:<16}  {c['domains'][0]}")
        return

    if args.school:
        school = get(args.school.lower())
        if not school:
            print(f"! 未找到学校代码: {args.school}")
            cands = search(args.school)
            if cands:
                print("疑似匹配：")
                for c in cands:
                    print(f"   {c['code']:<12} {c['name']}")
            return
        schools = [school]
    else:
        from src.selector import select_universities
        schools = select_universities()

    print(f"\n已选择 {len(schools)} 所学校：{[s['name'] for s in schools]}")

    # ---- 工具与库自检 ----
    print("\n[预检]")
    print(f"  - 本地CVE库: {LOCAL_CVE_PATHS.get('cve_root')} "
          f"(存在={Path(LOCAL_CVE_PATHS.get('cve_root','')).exists()})")
    print(f"  - 本地PoC库: {LOCAL_CVE_PATHS.get('exploitarium')} "
          f"(存在={Path(LOCAL_CVE_PATHS.get('exploitarium','')).exists()})")
    for t in ["subfinder", "nuclei", "httpx"]:
        print(f"  - 工具[{t}]: {'✓ 可用' if which(t) else '✗ 未装(自动降级)'}")

    # ---- 逐校执行 ----
    for school in schools:
        print(f"\n{'='*60}\n  处理: {school['name']} ({school['code']})\n{'='*60}")
        out_dir = output_dir_for(school["code"])

        # 1. 资产收集
        subdomains = collect_assets(school, use_external=args.external)

        # 2. 探活指纹
        alive = probe_assets(subdomains, school["code"])

        # 3. 漏洞挖掘
        findings, nday = [], []
        poc_projects = index_exploitarium()
        poc_hits = match_pocs(" ".join(
            [str(fp.get("server", "")) for fp in alive]), poc_projects)
        if not args.no_scan:
            findings, nday = run_vuln_engine(alive, school["code"], do_sensitive=True)
        else:
            print(f"\n[*] 跳过漏洞挖掘 (--no-scan)")

        # 4. 复测
        reverify_out = None
        if findings and not args.recon_only:
            reverify_out = reverify(school["code"])

        # 5. 报告
        if not args.recon_only:
            rp = build_report(
                school, alive, findings, nday,
                reverify_out=reverify_out,
                poc_hits=poc_hits,
                assets_info={"assets": len(subdomains), "alive": len(alive)},
            )
            default_manager().register(rp, school, {"confirmed_vulns": len(findings)})
            print(f"[*] 报告已生成并登记: {rp}")
        else:
            print("\n(仅资产收集模式)")

    print(f"\n{'='*60}\n  全部完成，结果输出目录: outputs\\\n{'='*60}")


if __name__ == "__main__":
    main()