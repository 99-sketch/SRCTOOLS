# -*- coding: utf-8 -*-
"""报告生成离线自测：验证含主动漏洞+攻击日志的报告能正确渲染"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.report.generator import build_report

school = {"name": "测试大学", "code": "selftest", "domains": ["test.edu.cn"]}

findings = [
    {"url": "http://a.test.edu.cn/list.jsp?id=1", "type": "SQL注入(error-based)",
     "sev": "严重", "method": "GET", "confirm": "true-positive",
     "source": "active-exploit",
     "evidence": {"param": "id", "payload": "1'",
                  "request": "GET http://a.test.edu.cn/list.jsp?id=1%27",
                  "response_line": "HTTP/1.1 200 OK",
                  "response_snippet": "Warning: mysql_fetch_array() ... SQL syntax error",
                  "verification": "单引号报错签名命中"}},
    {"url": "http://b.test.edu.cn/news.jsp?title=x", "type": "Reflected XSS",
     "sev": "中", "confirm": "true-positive", "source": "active-exploit",
     "evidence": {"param": "title", "payload": "<img src=x onerror=mark>",
                  "response_snippet": "<p><img src=x onerror=mark></p>",
                  "verification": "payload原样反射"}},
    {"url": "http://c.test.edu.cn/.git/config", "type": "Git源码仓库泄露(.git/config)",
     "sev": "高", "confirm": "true-positive", "source": "sensitive-disclosure",
     "evidence": {"request": "GET http://c.test.edu.cn/.git/config",
                  "response_snippet": "[core] ... repositoryformatversion = 0",
                  "verification": "HTTP200含[core]"}},
]

attack_log = [
    {"url": "http://a.test.edu.cn/list.jsp?id=1", "param": "id",
     "payload": "SQL注入探测", "status": "HTTP/1.1 200 OK", "verdict": "命中",
     "note": "SQL注入(error-based)"},
    {"url": "http://b.test.edu.cn/news.jsp?title=x", "param": "title",
     "payload": "<img src=x onerror=mark>", "status": "HTTP/1.1 200 OK",
     "verdict": "命中", "note": "Reflected XSS"},
    {"url": "http://d.test.edu.cn/search.jsp?q=hi", "param": "q",
     "payload": "<img src=x onerror=m2>", "status": "HTTP/1.1 200 OK",
     "verdict": "未命中", "note": ""},
]

od = Path(r"e:\trae自动化\edu-src-toolkit\outputs\selftest")
od.mkdir(parents=True, exist_ok=True)
(od / "findings.json").write_text(
    json.dumps({"findings": findings, "nday": [], "attack_log": attack_log},
               ensure_ascii=False), encoding="utf-8")

p = build_report(school, [], findings, [], None, assets_info={"assets": 12, "alive": 3})
t = p.read_text(encoding="utf-8")
checks = ["3.7 攻击执行明细", "SQL注入(error-based)", "Reflected XSS",
          "Git源码仓库泄露", "注入参数", "注入Payload", "✅命中", "⛔未命中",
          "3.4 主动渗透(注入验证)"]
ok = True
for kw in checks:
    found = kw in t
    ok = ok and found
    print(("FOUND" if found else "MISS "), kw)
print("\nRESULT:", "PASS ✅" if ok else "FAIL ❌")