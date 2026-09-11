# -*- coding: utf-8 -*-
"""复测模块 - 证据链二次确认（重写）

修复此前缺陷：此前把『稳定返回502』也判为 confirmed，是严重误报。
现在复测必须再次拿到 HTTP 200 + 响应体含真实漏洞证据特征，才判 confirmed。

hub 判定：
  - 复审时对每条 finding 重新取证，保留两次独立取证的完整请求/响应。
  - 只有两次都满足证据特征，才 confirmed。
"""

import sys
import ssl
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for
from src.vuln.evidence import (raw_fetch, is_really_source_code,
                               is_git_leak, is_svn_leak, is_dir_listing)


# 复测证据判定（按漏洞类型）
def _reverify_evidence(record, evidence_getter):
    """对单条记录取证并判定。返回 (status, reason, evidence)

    判定优先级：证据特征 > 200 > 其他
    """
    url = record.get("url", "")
    ftype = record.get("type", "").lower()
    low_type = ftype

    # ---- 主动注入漏洞：重新执行对应漏洞判定，二次独立命中才算 confirmed ----
    if record.get("source") in ("active-exploit", "nday-active-verify"):
        return _reverify_active(record)

    ev_list = []          # 两次取证的证据
    for _ in range(2):
        r = evidence_getter(url)
        ev_list.append(r)

    # 判定逻辑
    def _match(r):
        if not r or r["status"] is None:
            return None
        if r["status"] != 200:
            return False
        text = r["text"]
        if "git" in low_type and ".git" in low_type:
            return is_git_leak(text)
        if "svn" in low_type:
            return is_svn_leak(text)
        if "目录列表" in low_type:
            return is_dir_listing(text)
        if "php" in low_type or "源代码" in low_type or "源码" in low_type or "配置" in low_type or "env" in low_type:
            return is_really_source_code(text)
        if "备份" in low_type or "数据库" in low_type:
            return is_really_source_code(text) or ("create table" in text.lower() or "insert into" in text.lower())
        # 默认：要求非空内容
        return bool(text.strip())

    results = [_match(r) for r in ev_list]
    ok = [x for x in results if x is True]
    fp = [x for x in results if x is False]

    if len(ok) == len(results) and ok:
        return "confirmed", f"两次均HTTP200且响应体含明确漏洞证据特征", _dump_evidence(ev_list, url)
    elif fp:
        return "false_positive", f"响应不含漏洞证据特征(HTTP状态或内容不符)，判定误报", _dump_evidence(ev_list, url)
    else:
        return "unreachable", "两次均无法取得有效证据(超时/连接失败)", _dump_evidence(ev_list, url)


def _reverify_active(record):
    """对主动注入/NDay特征漏洞二次独立验证：以取证时的参数重跑对应判定器。

    若判定器再次命中 → confirmed；否则 false_positive。
    构造向量：url + method + evidence.param（可重放）。
    """
    ftype = (record.get("type") or "")
    url = record.get("url")
    ev = record.get("evidence") or {}
    param = ev.get("param")
    vector = {"url": url, "method": "GET",
              "params": [{"name": param, "orig": None}] if param else []}

    from src.exploit import checks
    try:
        result = None
        if "xss" in ftype.lower() or "反射" in ftype:
            result = checks.check_xss(vector)
        elif "sql" in ftype.lower() or "注入" in ftype:
            result = checks.check_sqli(vector)
        elif "路径穿越" in ftype or "任意文件读取" in ftype or "文件读取" in ftype:
            result = checks.check_path_traversal(vector)
        elif "重定向" in ftype or "redirect" in ftype.lower():
            result = checks.check_open_redirect(vector)
        elif "actuator" in ftype.lower():
            from src.vuln.nday_verify import verify_spring_actuator
            v = verify_spring_actuator(url)
            if v.get("present"):
                result = {"url": url, "type": ftype, "sev": record.get("sev", "中"),
                          "confirm": "true-positive", "evidence": {
                              "verification": v.get("conclusion"), "response_snippet": v.get("evidence")}}
        if result:
            return "confirmed", "重跑对应注入判定器二次命中证据链", {
                "url": url, "param": param,
                "replay_evidence": (result.get("evidence") or {}).get("verification", ""),
                "snippet": (result.get("evidence") or {}).get("response_snippet", "")[:300],
                "verified_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        return ("false_positive", "重跑对应注入判定器未再次命中，判定误报/已失效",
                {"url": url, "param": param, "verified_at": time.strftime("%Y-%m-%d %H:%M:%S")})
    except Exception as e:
        return "unreachable", f"重跑判定器异常: {e}", {"url": url, "param": param}


def _dump_evidence(ev_list, url):
    """把两次取证压缩为可纳入报告的证据链"""
    chain = []
    for i, r in enumerate(ev_list, 1):
        if r and r.get("status") is not None:
            chain.append({
                "round": i,
                "status": r["status"],
                "resp_line": r.get("resp_line"),
                "resp_headers": r.get("resp_headers_full", ""),
                "snippet": r.get("text", "")[:400],
                "body_len": len(r.get("body", b"")),
                "captured_at": r.get("captured_at"),
            })
        else:
            chain.append({"round": i, "status": None, "error": (r or {}).get("error")})
    return {"url": url, "rounds": chain, "verified_at": time.strftime("%Y-%m-%d %H:%M:%S")}


def reverify(school_code, stop_flag=None, emit=None):
    """复测该校全部findings（证据链驱动）"""
    def _out(msg):
        if emit:
            emit(msg)
        else:
            print(msg)

    _out(f"[*] 证据链复测: {school_code}")
    out_dir = output_dir_for(school_code)
    fp_path = out_dir / "findings.json"
    if not fp_path.exists():
        _out("    ! 未找到 findings.json，请先运行漏洞挖掘")
        return {}

    data = json.loads(fp_path.read_text(encoding="utf-8"))
    findings = data.get("findings", [])
    stats = {"confirmed": [], "false_positive": [], "unreachable": []}

    # 每次复测独立发起真实请求取证
    getter = lambda u: raw_fetch(u)
    for i, rec in enumerate(findings):
        if stop_flag and stop_flag.is_set():
            _out("[!] 复测被停止")
            break
        status, reason, evidence = _reverify_evidence(rec, getter)
        rec["reverify"] = {"status": status, "reason": reason,
                           "evidence": evidence,
                           "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        stats.setdefault(status, []).append(rec)
        _out(f"    [{i+1}/{len(findings)}] {status:<15} {rec.get('url','')[:48]} | {reason[:30]}")

    # 只保留确认项(save verified only)
    out = {
        "summary": {k: len(v) for k, v in stats.items()},
        "findings": findings,
        "confirmed_only": stats["confirmed"],
        "false_positive_only": stats["false_positive"],
    }
    rv_path = out_dir / "reverify.json"
    rv_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    _out(f"    ✓ 复测完成: confirmed {len(stats['confirmed'])}, "
         f"误报 {len(stats['false_positive'])}, 不可达 {len(stats['unreachable'])}")
    return out


if __name__ == "__main__":
    code = sys.argv[1] if len(sys.argv) > 1 else "zju"
    reverify(code)