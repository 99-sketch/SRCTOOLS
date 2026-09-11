# -*- coding: utf-8 -*-
"""证据引擎自检：验证修复是否生效（模拟此前误报场景）"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.vuln.evidence import (is_really_source_code, is_git_leak,
                                raw_fetch, check_sensitive, VULN_RULES, ARCHIVE_RULES)
from src.vuln.engine import find_nday_for_fingerprint
from src.report.generator import build_report

print("="*52)
print(" 证据引擎核心判定自检 (修复验证)")
print("="*52)

# 1. 真实PHP源码 → 应 True
r1 = is_really_source_code("<?php\n$db_host = 'localhost';\n$db_pass='secret';\nmysqli_connect($db_host);")
print(f"[1] 真实PHP源码判定: {r1}  {'✓' if r1 else '✗失败'}")

# 2. 错误页/502内容 → 应 False (修复点1)
r2 = is_really_source_code("<html><head><title>502 Bad Gateway</title></head><body>Bad Gateway</body></html>")
print(f"[2] 502错误页判定: {r2}  {'✓非漏洞' if not r2 else '✗仍误判!'}")

# 3. robots.txt → 不再是漏洞规则
rules = [r.path for r in VULN_RULES + ARCHIVE_RULES]
r3 = not any("/robots.txt" in p for p in rules)
print(f"[3] robots.txt已从漏洞规则移除: {r3} {'✓' if r3 else '✗'}")

# 4. 空/HTML首页 → 不是源码 → False
r4 = is_really_source_code("<html><body><h1>Welcome</h1><p>site</p></body></html>")
print(f"[4] 普通首页判定: {r4}  {'✓非漏洞' if not r4 else '✗误判'}")

# 5. git配置泄露 → True
r5 = is_git_leak("[core]\n\trepositoryformatversion = 0\n\tfilemode = true")
print(f"[5] .git/config判定: {r5}  {'✓' if r5 else '✗'}")

print("\n=== Nday精确匹配自检（消除apache宽泛误报）===")
# 模拟：目标指纹是 shiro，但本地库有apache其他项目CVE
fake_entries = [
    {"id": "CVE-2016-4437", "desc": "Apache Shiro RememberMe反序列化RCE"},
    {"id": "CVE-2014-3624", "desc": "Apache Traffic Server 访问绕过"},
    {"id": "CVE-2017-12633", "desc": "Apache Camel 反序列化RCE"},
    {"id": "CVE-2020-11989", "desc": "Apache Shiro 认证绕过"},
]
c = find_nday_for_fingerprint(["shiro"], entries=fake_entries)
cves = {x["cve"] for x in c}
ok_shiro1 = "CVE-2016-4437" in cves
ok_shiro2 = "CVE-2020-11989" in cves
ok_excl = ("CVE-2014-3624" not in cves) and ("CVE-2017-12633" not in cves)
print(f"  命中Shiro真CVE: {cves} ")
print(f"  [Shiro正确包含] {ok_shiro1 and ok_shiro2} {'✓' if ok_shiro1 and ok_shiro2 else '✗'}")
print(f"  [apache跨产品已排除] {ok_excl} {'✓' if ok_excl else '✗误报仍在!'}")

print("\n=== 报告生成自检（只收confirmed）===")
school = {"name":"自检大学","code":"selftest","domains":["t.edu.cn"]}
# 伪造：一条502假漏洞(confirm=base) + 一条带证据的真漏洞
findings = [
    {"url":"http://x.edu.cn/config.php.bak","type":"源码备份泄露","sev":"严重",
     "confirm":"base","reverify":{"status":"false_positive","reason":"502响应,误报"}},
    {"url":"http://x.edu.cn/.git/config","type":"Git源码仓库泄露","sev":"高",
     "confirm":"true-positive","evidence":{"request":"GET /",
        "response_line":"HTTP/1.1 200 OK",
        "response_headers":"Server: nginx",
        "response_snippet":"[core]\n\trepositoryformatversion = 0\n\tfilemode = true",
        "verification":"HTTP200且响应体含.git/config证据"}},
]
revertify_out = {"summary":{"confirmed":1,"false_positive":1,"unreachable":0},
                 "findings":findings}
rp = build_report(school, [{"url":"http://x.edu.cn/","status":200,"title":"X","hits":["shiro"],"server":"nginx"}],
                  findings, [{"fingerprint":"shiro","keyword":"shiro","cve":"CVE-2016-4437","desc":"Shiro反序列化"}],
                  reverify_out=revertify_out, assets_info={"assets":10,"alive":2})
import re
txt = Path(rp).read_text(encoding="utf-8")
confirmed = txt.count("### 4.")
print(f"  [报告生成] 路径存在: {rp.exists()} ")
print(f"  [已确认漏洞章节条目] {confirmed}  {'✓只含确认' if confirmed==1 else '✗数量不对'}")

# 502那条不应该进"已确认"
in_confirmed_section = txt.split("## 4 已确认")[1].split("## 5")[0] if "## 4 已确认" in txt else ""
has_502 = "502" in in_confirmed_section
print(f"  [502误报未进入确认区] {not has_502} {'✓' if not has_502 else '✗仍混入!'}")
print("\n全部自检完成")