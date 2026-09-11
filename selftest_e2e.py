# -*- coding: utf-8 -*-
"""端到端集成测试：本地模拟真实/伪漏洞服务器，验证证据引擎正确性"""
import sys, threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, str(Path(__file__).resolve().parent))

import json

# ---------- 本地模拟服务器 ----------
class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/config.php.bak":
            # 真实源码备份泄露 (应判为漏洞)
            body = "<?php\n$db_host='localhost';\n$db_user='root';\n$db_pass='secret123';\nmysqli_connect($db_host,$db_user,$db_pass);\n?>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/config.php.old":
            # 伪泄露：返回502错误页 (应判非漏洞)
            body = b"<html><head><title>502 Bad Gateway</title></head><body>nginx/1.18.0</body></html>"
            self.send_response(502)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/.git/config":
            body = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html><body><h1>Homepage</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, *a): pass

server = HTTPServer(("127.0.0.1", 0), MockHandler)
port = server.server_address[1]
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
base = f"http://127.0.0.1:{port}"
print(f"模拟服务器启动: {base}")

# ---------- 执行证据检测 ----------
from src.vuln.evidence import check_sensitive
findings = check_sensitive(base)
print("\n=== 证据引擎探测结果 ===")
for f in findings:
    print(f"  ✓ [确认] {f['type']} @ {f['url']}")
    print(f"      证据: {f['evidence']['response_line']} 验证={f['evidence']['verification']}")

types = [f["type"] for f in findings]
checks = {
    "config.php.bak源码泄露被确认": any("config.php.bak" in f["url"] and "备份泄露" in f["type"] for f in findings),
    "502伪泄露(config.php.old)未误报": not any("config.php.old" in f["url"] for f in findings),
    ".git泄露被确认": any(".git" in f["url"] for f in findings),
    "robots.txt未当漏洞": not any("robots" in f["url"] for f in findings),
}
print("\n=== 验证点 ===")
allok = True
for name, ok in checks.items():
    print(f"  [{'✓' if ok else '✗'}] {name}")
    allok = allok and ok
print(f"\n{'=== 端到端集成测试全部通过 ===' if allok else '!!! 存在失败项 !!!'}")
server.shutdown()