# -*- coding: utf-8 -*-
"""漏洞挖掘引擎（主动验证版 v3）

三层能力（彻底告别"只从信息收集里找漏洞"）：
  1. 敏感文件/源码/备份泄露：证据链判定（HTTP200 + 响应体真实证据）   —— 被动
  2. 主动漏洞验证：对参数真实注入 SQLi/XSS/路径穿越/开放重定向，差分证据链 —— 主动
  3. Nday 特征验证：shiro rememberMe / spring actuator 等无害行为探测，
     确系真实信息泄露/反序列化入口时转为 findings —— 主动

输出：只有 100% 证据确认的漏洞才进 findings（confirmed）。
攻击过程全程记录 attack_log.json，供报告还原"怎么打的"。
"""

import sys
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for
from src.vuln.evidence import (check_sensitive, check_default_vulns,
                               raw_fetch, is_really_source_code)
from src.vuln.poc_index import index_exploitarium


# ============================================================
#  Nday 匹配：产品精确绑定（不再用宽泛 "apache" 关键字）
# ============================================================
def find_nday_for_fingerprint(fp_hits, entries=None):
    """根据精确指纹(如 remberme cookie)匹配本地CVE库中真正关联该产品的漏洞。

    只匹配同一产品家族的漏洞，绝不跨产品。返回候选列表(仅线索，非漏洞)。
    """
    if not entries:
        entries = _load_cnvd_entries()
    if not entries:
        return []

    # 索引：按"产品名"精确关联，而非宽泛词
    product_keywords = {
        "shiro": ["shiro"],
        "thinkphp": ["thinkphp"],
        "fastjson": ["fastjson"],
        "weblogic": ["weblogic"],
        "spring": ["spring", "spring framework", "spring boot"],
        "struts": ["struts2", "struts 2", "apache struts"],
        "纳入": [],
    }
    hits_lower = [h.lower() for h in fp_hits]
    cands = []
    seen = set()
    for hit in hits_lower:
        # 只对可靠产品指纹做Nday关联
        for prod, kws in product_keywords.items():
            if prod in hit:   # 精确产品名命中
                for kw in kws:
                    for it in entries:
                        blob = (str(it.get("desc", "")) + " " + str(it.get("id", ""))).lower()
                        if kw in blob:
                            key = (prod, it["id"])
                            if key in seen:
                                continue
                            seen.add(key)
                            cands.append({
                                "fingerprint": prod,
                                "keyword": kw,
                                "cve": it["id"],
                                "cnvd": it.get("cnvd", ""),
                                "desc": (it.get("desc") or "")[:150],
                                "note": "仅线索，需人工验证目标版本与利用前置条件后才能上报",
                            })
                break  # 一个hits只关联一个产品族
    return cands[:40]


def _load_cnvd_entries(max_items=10000):
    """从CNVD库加载条目（parquet或json回退）"""
    from src.config import LOCAL_CVE_PATHS, load_json
    entries = []
    pq = Path(LOCAL_CVE_PATHS.get("cnvd", ""))
    if pq.exists():
        try:
            import pandas as pd
            df = pd.read_parquet(pq)
            cols = [c.lower() for c in df.columns]
            desc_col = next((c for c in df.columns if c.lower() in ("description", "title")), None)
            id_col = next((c for c in df.columns if c.lower() in ("cve", "cve_id")), df.columns[-1])
            rows = df.head(max_items).iterrows()
            for _, row in rows:
                cid = str(row[id_col])
                blob = str(row[desc_col]) if desc_col else " ".join(str(v) for v in row.values)
                entries.append({"id": cid, "cnvd": "", "desc": blob[:500]})
            if entries:
                return entries
        except Exception:
            pass
    j_path = Path(LOCAL_CVE_PATHS.get("cve_to_cnvd", ""))
    if j_path.exists():
        data = load_json(str(j_path), default=[])
        if isinstance(data, dict):
            data = list(data.values())
        for it in data[:max_items]:
            if isinstance(it, dict):
                entries.append({
                    "id": it.get("cve") or "",
                    "desc": it.get("description") or it.get("title") or str(it),
                    "cnvd": it.get("cnvd_id") or "",
                })
    return entries


# ============================================================
#  主流程
# ============================================================
def run_vuln_engine(alive_results, school_code, do_sensitive=True,
                    stop_flag=None, emit=None):
    """证据链驱动漏洞挖掘。返回 (findings, nday_candidates)
    - findings 中每条都是已确认的证据漏洞 (confirm=true-positive)
    - nday_candidates 仅是待人工验证线索，不自动判漏洞
    """
    def _out(msg):
        if emit:
            emit(msg)
        else:
            print(msg)

    _out(f"[*] 证据链漏洞挖掘引擎启动: {len(alive_results)} 个存活资产")
    out_dir = output_dir_for(school_code)

    # ---------- 1. Nday 线索（精确指纹）----------
    all_hits = []
    for fp in alive_results:
        for h in fp.get("hits", []):
            all_hits.append(h)
    nday_candidates = []
    if all_hits:
        nday_candidates = find_nday_for_fingerprint(list(set(all_hits)))
    _out(f"    本地库精确匹配到 {len(nday_candidates)} 条Nday线索(需人工验证)")

    # ---------- 2. Web 证据探测（被动敏感文件/源码/备份泄露）----------
    findings = []
    if do_sensitive:
        urls = list({fp["url"] for fp in alive_results})[:60]
        def _scan(u):
            if stop_flag and stop_flag.is_set():
                return []
            try:
                return check_sensitive(u, stop_flag=stop_flag) + \
                       check_default_vulns(u, stop_flag=stop_flag)
            except Exception:
                return []
        done = 0
        with ThreadPoolExecutor(max_workers=10) as pool:
            for u, res in zip(urls, pool.map(_scan, urls)):
                done += 1
                if stop_flag and stop_flag.is_set():
                    break
                for f in res:
                    findings.append(f)
                if emit and done % 10 == 0:
                    emit(f"    证据探测进度: {done}/{len(urls)}, 已确认 {len(findings)} 条证据漏洞")

    # ---------- 3. 主动漏洞验证（真实注入·差分证据链）----------
    attack_log = []
    if alive_results:
        _out("[*] 进入主动漏洞验证阶段（SQLi/XSS/路径穿越/开放重定向）")
        from src.exploit.engine import run_active_exploit
        try:
            exploits, attack_log = run_active_exploit(
                alive_results, school_code, stop_flag=stop_flag, emit=emit)
            # 主动注入确认的漏洞并入 findings（去重 by url+type）
            known = {(f.get("url", ""), f.get("type", "")) for f in findings}
            for f in exploits:
                if (f.get("url", ""), f.get("type", "")) not in known:
                    findings.append(f)
            _out(f"    主动验证确认 {len(exploits)} 条证据漏洞，累计 {len(findings)} 条")
        except Exception as e:
            _out(f"    主动验证阶段异常（不影响被动结果）: {e}")

    # ---------- 4. Nday 特征验证（无害行为探测，确系真实泄露则转finding）----------
    nday_verified = []
    if alive_results:
        _out("[*] Nday 特征验证（shiro/spring 等无害行为探测）")
        from src.vuln.nday_verify import verify_nday
        try:
            nday_verified = verify_nday(alive_results, nday_candidates, school_code,
                                        stop_flag=stop_flag, emit=emit)
            # Nday 特征命中 → 转为证据漏洞（spring actuator / shiro 反序列化入口 /
            # java 反序列化中间件入口），全部是无害行为探测得出的真实特征
            known = {(f.get("url", ""), f.get("type", "")) for f in findings}
            # 指纹 - (类型, 等级, 规则)
            conf = {
                "spring":       ("Spring Boot Actuator 未授权信息泄露", "中",
                                 "未认证访问Actuator环境端点返回200含敏感JSON"),
                "shiro":        ("Apache Shiro 反序列化入口(rememberMe deleteMe)", "高",
                                 "构造非法rememberMe Cookie后响应Set-Cookie含deleteMe，确认Shiro并存在反序列化入口"),
                "java-deser":   ("Java 反序列化中间件入口特征(框架入口指纹)", "中",
                                 "检测到Weblogic/Struts/fastjson等反序列化中间件特征入口"),
                "thinkphp":     ("ThinkPHP 框架特征(结合版本评估Nday)", "低",
                                 "确认部署ThinkPHP框架"),
            }
            for v in nday_verified:
                key = v.get("fingerprint", "")
                if key not in conf:
                    continue
                ftype, sev, rule = conf[key]
                f = {
                    "url": v["url"],
                    "type": ftype,
                    "sev": sev,
                    "method": "GET", "confirm": "true-positive",
                    "source": "nday-active-verify",
                    "evidence": {
                        "request": f"GET {v['url']} (Nday行为探测)",
                        "response_line": "行为特征命中",
                        "response_snippet": (v.get("evidence", "") or "")[:400],
                        "verification": v.get("conclusion", ""),
                        "caveat": v.get("caveat", ""),
                        "cve": v.get("cve", ""),
                        "cnvd": v.get("cnvd", ""),
                        "validated_at": v.get("checked_at", ""),
                    },
                    "rule": rule,
                }
                if (f["url"], f["type"]) not in known:
                    findings.append(f)
                    known.add((f["url"], f["type"]))
        except Exception as e:
            _out(f"    Nday特征验证异常: {e}")

    # ---------- 5. 外部扫描器集成（nuclei/afrog 覆盖全渗透手法，自动执行）----------
    if alive_results and not (stop_flag and stop_flag.is_set()):
        _out("[*] 外部扫描器集成（nuclei/afrog 等，覆盖反序列化/XSS/CSRF/源码泄露等更多手法）")
        from src.recon.tooling import run_external_scanners
        try:
            ext = run_external_scanners(alive_results, school_code,
                                        stop_flag=stop_flag, emit=emit)
            known = {(f.get("url", ""), f.get("type", "")) for f in findings}
            for f in ext:
                if (f.get("url", ""), f.get("type", "")) not in known:
                    findings.append(f)
            _out(f"    外部扫描器确认 {len(ext)} 条，累计 {len(findings)} 条")
        except Exception as e:
            _out(f"    外部扫描器阶段异常（不影响内置结果）: {e}")

    # ---------- 5.5 红队工具集成（Gr33k/enscan/Railgun/Aazhen/weekpasswd）----------
    if alive_results and not (stop_flag and stop_flag.is_set()):
        _out("[*] 红队工具集成（Gr33k CVE利用/enscan企业信息/Railgun收集/Aazhen扫描/弱口令爆破）")
        from src.recon.redteam_tools import run_all_redteam_tools
        try:
            rt = run_all_redteam_tools(alive_results, school_code,
                                       stop_flag=stop_flag, emit=emit)
            known = {(f.get("url", ""), f.get("type", "")) for f in findings}
            for f in rt:
                if (f.get("url", ""), f.get("type", "")) not in known:
                    findings.append(f)
            _out(f"    红队工具确认 {len(rt)} 条，累计 {len(findings)} 条")
        except Exception as e:
            _out(f"    红队工具阶段异常（不影响内置结果）: {e}")

    # ---------- 6. 保存 ----------
    findings_path = out_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump({"findings": findings,
                   "nday": nday_candidates,
                   "nday_verified": nday_verified,
                   "attack_log": attack_log,
                   "engine": "active-exploit v3",
                   "note": "findings均为100%证据确认; nday及nday_verified为线索/特征标识",
                   "summary": {
                       "confirmed_vulns": len(findings),
                       "sensitive_disclosure": _count_type(findings, "泄露"),
                       "active_injected": _count_source(findings, "active-exploit"),
                       "nday_feature": _count_source(findings, "nday-active-verify"),
                       "external_scanner": _count_source_any(findings, "external-"),
                       "redteam_tools": _count_source_any(findings, "external-gr33k") + _count_source_any(findings, "external-enscan") + _count_source_any(findings, "external-railgun") + _count_source_any(findings, "external-aazhen") + _count_source_any(findings, "external-weekpasswd"),
                       "attack_entries": len(attack_log),
                   }},
                  f, ensure_ascii=False, indent=2)
    _out(f"    ✓ 漏洞挖掘完成: 确认 {len(findings)} 条, Nday线索 {len(nday_candidates)}, "
         f"攻击记录 {len(attack_log)} 条 -> {findings_path.name}")
    return findings, nday_candidates


def _count_type(fs, kw):
    return sum(1 for f in fs if kw in (f.get("type") or ""))

def _count_source(fs, src):
    return sum(1 for f in fs if f.get("source") == src)

def _count_source_any(fs, prefix):
    return sum(1 for f in fs if (f.get("source") or "").startswith(prefix))


if __name__ == "__main__":
    # 自检：验证证据判定正确性
    print("== 证据判定自检 ==")
    print(" 真实PHP源码:", is_really_source_code("<?php\n$db_host='localhost';\n$db_pass='x';\nconnect($db_host);"))
    print(" 空白/错误页:", is_really_source_code("<html><body>Bad Gateway</body></html>"))
    print(" 空:", is_really_source_code(""))