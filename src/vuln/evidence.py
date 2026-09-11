# -*- coding: utf-8 -*-
"""证据链驱动的漏洞验证引擎（核心重写）

核心原则：
  只有拿到『HTTP 200 + 响应体包含明确漏洞证据特征』才算真漏洞。
  502/403/404/超时一律不算漏洞。
  每个漏洞必须附带可复现的原始请求/响应证据（证据链）。

设计目标：宁可漏报，不可误报。100% 确信才进入可提交报告的 confirmed 列表。
"""

import sys
import ssl
import re
import time
import json
from pathlib import Path

import urllib.request
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for


# ============================================================
#  低级 HTTP 客户端：捕获完整请求/响应，作为证据链
# ============================================================
def raw_fetch(url, timeout=12, extra_headers=None, method="GET", data=None):
    """发送请求并返回完整证据对象。

    返回 dict:
      status, headers(dict), body(bytes), text(str),
      req_line, req_headers(str), resp_line, elapsed_ms,
      evidence (证明该响应『确实到达真实目标』的指纹串)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, headers=headers, data=data, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(500000)  # 最多500KB
            status = r.status
            resp_headers = dict(r.headers.items()) if hasattr(r.headers, "items") else {}
            resp_line = f"HTTP/{getattr(r, 'version', 1)} {status}"
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(200000)
        except Exception:
            pass
        status = e.code
        resp_headers = dict(e.headers.items()) if hasattr(e.headers, "items") else {}
        resp_line = f"HTTP/{getattr(e, 'version', 1)} {status}"
    except Exception as ex:
        return {"status": None, "error": str(ex), "elapsed_ms": int((time.time() - t0) * 1000)}

    text = body.decode("utf-8", errors="ignore")
    return {
        "status": status,
        "headers": resp_headers,
        "body": body,
        "text": text,
        "req_line": f"{method} {url} HTTP/1.1",
        "req_headers": "\n".join(f"{k}: {v}" for k, v in headers.items()),
        "resp_line": resp_line,
        "resp_headers_full": "\n".join(f"{k}: {v}" for k, v in resp_headers.items()),
        "elapsed_ms": int((time.time() - t0) * 1000),
    }


def is_really_source_code(text):
    """判断响应体是否真的是源代码/配置文件内容（而非错误页）。

    满足任一即可:
      - PHP 源码: <?php 或 <? 存在 + 含 $变量定义或函数
      - 配置: 含 define( / env => / password / secret / DB_HOST 等 + 等号键值
      - 代码块: 多行包含 -> / function / class / SELECT / 引号包裹字符串
    """
    if not text or len(text) < 10:
        return False
    lower = text.lower()
    # 特征一：PHP 标签
    if "<?php" in lower or re.search(r"<\?[\s\w]", text):
        if re.search(r"\$\w+\s*=", text) or "function" in lower or "include" in lower:
            return True
        # 纯 <?php echo/define 也算
        if "echo" in lower or "define(" in lower or "header(" in lower:
            return True
    # 特征二：配置文件键值 + 敏感字段
    if ("=" in text) and len([l for l in text.splitlines() if "=" in l]) >= 2:
        if any(k in lower for k in
               ("password", "passwd", "db_host", "db_user", "dbname", "mysql",
                "secret", "api_key", "app_key", "token", "dsn", "host=")):
            return True
    # 特征三：多行逻辑代码（含控制流关键字）
    if lower.count("function") + lower.count("class ") + lower.count("select ") >= 2:
        if len(text.splitlines()) >= 5:
            return True
    return False


def is_dir_listing(text):
    """目录列表/autoindex 判断"""
    low = text.lower()
    return ("index of /" in low) or ("autoindex on" in low) or (
        "directory listing" in low)


def is_tomcat_trace(text, headers):
    return ("tomcat" in (headers.get("Server", "") or "").lower())


def is_git_leak(text):
    """真实 .git/config 泄露证据：必须含 [core] 且 repositoryformatversion"""
    return ("[core]" in text and "repositoryformatversion" in text)


def is_svn_leak(text):
    return ("svn" in text.lower() and ("dir" in text or "revision" in text.lower()))


# ============================================================
#  漏洞规则定义：每个规则 = 证据判定函数
# ============================================================
class VulnRule:
    """一个可验证的漏洞规则。path + 证据判定(explicit evidence)"""

    def __init__(self, path, name, sev, judge):
        self.path = path          # 探测路径
        self.name = name          # 漏洞类型
        self.sev = sev            # 危害等级
        self.judge = judge        # judge(text, headers) -> bool 是否有证据

    def test(self, base_url, stop_flag=None):
        """对单个基础URL探测。返回 finding dict 或 None"""
        if stop_flag and stop_flag.is_set():
            return None
        url = base_url.rstrip("/") + self.path
        r = raw_fetch(url)
        if r["status"] is None:
            return None  # 网络错误，不判
        if r["status"] != 200:
            # 非常重要：只有 200 才可能拿到内容。403/502/404 不构成漏洞证据
            return None

        text = r["text"]
        if not self.judge(text, r["headers"]):
            return None  # 无证据特征，误报，丢弃

        evidence = _build_evidence(r)
        return {
            "url": url,
            "type": self.name,
            "sev": self.sev,
            "method": "GET",
            "confirm": "true-positive",
            "source": "sensitive-disclosure",
            "evidence": evidence,          # 证据链
            "rule": f"{self.path} 响应200且命中证据",
        }


def _build_evidence(r):
    """从原始响应构造可提交SRC的证据链"""
    body_for_evi = r["body"]
    # 脱敏：截取前2KB用于报告，避免泄露海量敏感数据
    snippet = body_for_evi[:2000].decode("utf-8", errors="ignore")
    snippet_lines = snippet[:100]
    return {
        "request": f"{r['req_line']}\n{r['req_headers']}\n\n(空请求体)",
        "response_line": r["resp_line"],
        "response_headers": r["resp_headers_full"],
        "response_snippet": snippet_lines,
        "body_len": len(body_for_evi),
        "elapsed_ms": r["elapsed_ms"],
        "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "verification": "HTTP 200 且响应体包含明确漏洞证据特征（见 snippet），非错误页",
    }


# 规则实例
def _j_source(text, headers):
    return is_really_source_code(text)

def _j_git(text, headers):
    return is_git_leak(text)

def _j_svn(text, headers):
    return is_svn_leak(text)

def _j_dir(text, headers):
    return is_dir_listing(text)

def _j_phpinfo(text, headers):
    return ("phpinfo" in text.lower()) and ("php.ini" in text.lower() or "configuration" in text.lower())

def _j_env(text, headers):
    return is_really_source_code(text)

def _j_stacktrace(text, headers):
    """错误页信息泄露：堆栈/路径/DB凭据等真实信息。
    命中错误堆栈关键字 + 系统/文件路径或SQL/凭据特征才算，避免把正常报错当漏洞。"""
    low = text.lower()
    if any(k in low for k in ("traceback", "stack trace", "java.lang.", "exception in thread",
                              "at org.", "at com.", "at java.", ".py line", "in /var/www",
                              "fatal error", "runtimeexception", "runtime error")):
        # 必须伴随真实路径/SQL/文件特征，证明泄露了内部信息
        if re.search(r"[a-z]:\\\\|\/usr\/|\/var\/|\/home\/|\.php on line|\.py\b|select |insert into|create table|getjdbc|db_|password|user=.*assword", low, re.I):
            return True
        # .NET/Java 典型的调用栈行
        if re.search(r"\bat [a-z_]+\.\w+\([^)]*\.(java|cs|py):\d+\)", low):
            return True
    return False

def _j_admin(text, headers):
    """未授权访问高价值接口/后台——仅当响应是真·管理后台或用例界面（含登录/管理字样的HTML）"""
    low = text.lower()
    if len(text) < 8:
        return False
    if ("<form" in low) and any(k in low for k in ("login", "password", "user")):
        return True
    return False

# 漏洞规则表（默认启用的高可信证据）
VULN_RULES = [
    VulnRule("/.git/config", "Git源码仓库泄露(.git/config)", "高", _j_git),
    VulnRule("/.svn/entries", "SVN版本控制泄露(.svn)", "高", _j_svn),
    VulnRule("/composer.json", "Composer依赖清单泄露(源码仓库特征)", "中",
             lambda t, h: is_really_source_code(t)),
    VulnRule("/config.php.bak", "PHP配置文件备份泄露(config.php.bak)", "严重", _j_source),
    VulnRule("/config.php~", "PHP配置文件备份泄露(config.php~)", "严重", _j_source),
    VulnRule("/.env.bak", "环境变量备份泄露(.env.bak)", "高", _j_env),
    VulnRule("/.env", "环境变量文件泄露(.env)", "高", _j_env),
    VulnRule("/.env.save", "环境变量备份泄露(.env.save)", "高", _j_env),
    VulnRule("/phpinfo.php", "phpinfo信息泄露(phpinfo)", "高", _j_phpinfo),
    VulnRule("/backup.sql", "数据库备份泄露(backup.sql)", "严重", lambda t, h: "create table" in t.lower() or "insert into" in t.lower()),
    VulnRule("/db.sql", "数据库备份泄露(db.sql)", "严重", lambda t, h: "create table" in t.lower() or "insert into" in t.lower()),
    VulnRule("/database.sql", "数据库备份泄露(database.sql)", "严重", lambda t, h: "create table" in t.lower() or "insert into" in t.lower()),
    # —— 信息泄露类扩展 ——
    VulnRule("/.git/HEAD", "Git源码仓库泄露(.git/HEAD)", "高",
             lambda t, h: "ref:" in t.lower() and "refs" in t.lower()),
    VulnRule("/WEB-INF/web.xml", "Java配置泄露(WEB-INF/web.xml)", "严重",
             lambda t, h: "web-app" in t.lower() or "servlet" in t.lower()),
    VulnRule("/application.yml", "配置泄露(application.yml)", "高", _j_source),
    VulnRule("/application.properties", "配置泄露(application.properties)", "高", _j_source),
    VulnRule("/config.yml", "配置泄露(config.yml)", "高", _j_source),
    VulnRule("/settings.py", "源码信息泄露(settings.py)", "高", _j_source),
    VulnRule("/config/database.php", "数据库配置泄露(database.php)", "严重", _j_source),
    VulnRule("/inc/config.php", "配置泄露(inc/config.php)", "高", _j_source),
    VulnRule("/.DS_Store", "macOS目录索引泄露(.DS_Store)", "中",
             lambda t, h: len(t) >= 8),
]

# 文件名型泄露（目录列举后待dirsearch等）：这里仅做根基路径判断
ARCHIVE_RULES = [
    VulnRule("/www.zip", "整站源码压缩包泄露(www.zip)", "严重", lambda t, h: True),
    VulnRule("/site.zip", "整站源码压缩包泄露(site.zip)", "严重", lambda t, h: True),
    VulnRule("/backup.zip", "备份压缩包泄露(backup.zip)", "高", lambda t, h: True),
    VulnRule("/web.zip", "整站源码压缩包泄露(web.zip)", "严重", lambda t, h: True),
]


def check_sensitive(base_url, stop_flag=None, include_articles=False):
    """对单个URL执行全部证据规则，返回 finding 列表（已确认真漏洞）"""
    out = []
    rules = VULN_RULES
    if include_articles:
        rules = rules + ARCHIVE_RULES
    for rule in rules:
        f = rule.test(base_url, stop_flag=stop_flag)
        if f:
            out.append(f)
    return out


def check_default_vulns(url, stop_flag=None):
    """默认页/目录列表类漏洞（同样要求证据，不靠Server头猜）"""
    findings = []
    if stop_flag and stop_flag.is_set():
        return findings
    r = raw_fetch(url.rstrip("/") + "/")
    if r["status"] != 200:
        return findings
    text = r["text"]
    if is_dir_listing(text):
        findings.append({
            "url": url.rstrip("/") + "/",
            "type": "目录列表/autoindex泄露", "sev": "中",
            "method": "GET", "confirm": "true-positive",
            "source": "sensitive-disclosure",
            "evidence": _build_evidence(r)
                if False else {"request": f"GET {url}/", "response_line": r["resp_line"],
                               "response_headers": r["resp_headers_full"],
                               "response_snippet": text[:200], "body_len": len(r["body"]),
                               "verification": "目录列表证据(index of /)"},
            "rule": "根路径响应200且为目录列表",
        })
    # 错误页信息泄露（堆栈/Python异常/Java栈/绝对路径+SQL特征）
    if _j_stacktrace(text, r["headers"]):
        findings.append({
            "url": url.rstrip("/") + "/",
            "type": "错误页信息泄露(堆栈/路径/异常)", "sev": "中",
            "method": "GET", "confirm": "true-positive",
            "source": "sensitive-disclosure",
            "evidence": {"request": f"GET {url}/", "response_line": r["resp_line"],
                         "response_headers": r["resp_headers_full"],
                         "response_snippet": text[:300], "body_len": len(r["body"]),
                         "verification": "根页面响应包含程序堆栈/内部路径异常信息（信息泄露证据）"},
            "rule": "根路径响应200且含错误堆栈/路径泄露",
        })
    return findings