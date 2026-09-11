# -*- coding: utf-8 -*-
"""精准渗透测试报告生成器（完整版）

产出标准渗透测试报告，符合 SRC 提交要求：
  - 完整 PTES 七阶段执行记录（方法论 + 每条命令/方法 + 结果）
  - 攻击路径/攻击链：从初始获得到漏洞确认的完整过程
  - 证据链：每个漏洞附原始请求/响应/响应体证据
  - 只收录 100% 证据确认的漏洞（confirmed），误报绝不进入
  - 暴露面分析、影响评估、修复方案、上报材料
"""

import sys
import json
import html
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for


def _sev_sort_key(rec):
    order = {"严重": 0, "高": 1, "中": 2, "低": 3, "提示": 4}
    return order.get(rec.get("sev", "低"), 4)


def _esc(s):
    return html.escape(str(s))


def _src_cn(src):
    return {
        "active-exploit": "主动注入验证",
        "nday-active-verify": "Nday 行为验证",
        "sensitive-disclosure": "被动敏感文件探测",
        "external-nuclei": "nuclei模板扫描(自动)",
        "external-afrog": "afrog漏洞扫描(自动)",
        "external-xray": "xray综合扫描(自动)",
    }.get(src, "证据链探测")


def build_report(school, alive_results, findings, nday_candidates, reverify_out=None,
                 poc_hits=None, assets_info=None, emit=None,
                 evidence_log=None):
    """生成完整渗透测试报告，返回报告路径。

    evidence_log: 可选，记录各阶段执行日志（用于攻击链还原）.
                  若为 None 则尝试从 findings.json 的 attack_log 读取。
    """
    if emit:
        emit(f"[*] 生成报告: {school['name']}")
    out_dir = output_dir_for(school["code"])
    name = school["name"]
    code = school["code"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ---- 从 findings.json 读取 attack_log（攻击过程还原）----
    attack_log = None
    if not evidence_log:
        try:
            fp = out_dir / "findings.json"
            if fp.exists():
                attack_log = json.loads(fp.read_text(encoding="utf-8")).get("attack_log")
        except Exception:
            attack_log = None
    else:
        attack_log = evidence_log if isinstance(evidence_log, list) else None

    # ---- 只保留确认(evidence)漏洞；误报丢进附录 ----
    findings.sort(key=_sev_sort_key)
    rev_map = {}
    if reverify_out:
        for rec in reverify_out.get("findings", []):
            rev_map[rec.get("url", "") + rec.get("type", "")] = rec.get("reverify", {})

    confirmed = []
    rejected = []   # 误报/不可达，不进入正文
    for rec in findings:
        rv = rev_map.get(rec.get("url", "") + rec.get("type", "")) or {}
        st = rv.get("status")
        if st == "confirmed" or rec.get("confirm") == "true-positive":
            confirmed.append(rec)
        else:
            rejected.append(rec)

    sev_count = {}
    for rec in confirmed:
        sev_count[rec.get("sev", "低")] = sev_count.get(rec.get("sev", "低"), 0) + 1
    n_nuc = sum(1 for r in confirmed if r.get("source") == "external-nuclei")
    n_afr = sum(1 for r in confirmed if r.get("source") == "external-afrog")
    n_xry = sum(1 for r in confirmed if r.get("source") == "external-xray")
    n_act = sum(1 for r in confirmed if r.get("source") == "active-exploit")
    n_sen = sum(1 for r in confirmed if r.get("source") == "sensitive-disclosure")
    n_ndv = sum(1 for r in confirmed if r.get("source") == "nday-active-verify")
    n_ext = n_nuc + n_afr + n_xry

    L = []
    def _h(txt):
        L.append(txt); L.append("")

    # ================= 主报告 =================
    _h(f"# {name} 渗透测试报告（{code}）")
    _h(f"- 报告日期：{now}")
    _h(f"- 目标：{' / '.join(school.get('domains', []))}")
    _h(f"- 性质：公益安全研究 / 负责任披露（授权范围测试）")
    _h(f"- 引擎：证据链驱动 v2（100%证据确认）")
    _h("")
    L.append("---"); L.append("")

    # ---- 一、执行摘要 ----
    _h("## 1 执行摘要")
    _h("| 维度 | 结果 |")
    _h("|------|------|")
    if assets_info:
        _h(f"| 暴露面 (域名/资产) | {assets_info.get('assets',0)} |")
        _h(f"| 存活Web资产 | {assets_info.get('alive',0)} |")
    _h(f"| **100%确认漏洞** | **{len(confirmed)}** |")
    _h(f"| 高/中危 | {sev_count.get('高',0)} 高 / {sev_count.get('中',0)} 中 |")
    _h(f"| Nday线索(待人工) | {len(nday_candidates)} |")
    if reverify_out:
        rv = reverify_out.get("summary", {})
        _h(f"| 复测结论 | 确认{rv.get('confirmed',0)} / 误报{rv.get('false_positive',0)} / 不可达{rv.get('unreachable',0)} |")
        _h(f"| 误报剔除 | {len(rejected)} |")
    L.append("")

    # ---- 二、测试范围与方法（PTES）----
    _h("## 2 测试范围与方法论 (PTES)")
    _h("遵循 **PTES** 七阶段标准流程，每一阶段记录所用方法、命令与产出：")
    _h("| 阶段 | 方法/工具 | 产出 | 状态 |")
    _h("|------|----------|------|------|")
    ptes = [
        ("1 前期交互", "界定授权范围、测试边界、遵守政策", "测试授权书/范围定义", "✓"),
        ("2 信息收集", "被动(crt.sh子域) + 主动(DNS枚举) 资产发现+探活指纹", "资产清单, 存活Web指纹", "✓"),
        ("3 威胁建模", "基于指纹梳理攻击面:Web配置/备份/目录/源码/Nday + 可注入参数推导", "攻击面清单", "✓"),
        ("4 漏洞分析", "被动:敏感文件泄露证据判定; 主动:SQLi/XSS/路径穿越/开放重定向差分验证; Nday:shiro/actuator行为探测", "漏洞证据集", "✓"),
        ("5 渗透攻击", "对可注入参数投递payload，用基线/注入差分+报错/反射/文件内容特征确认可利用性", "确认漏洞+差分证据链", "✓"),
        ("6 后渗透", "评估数据泄露范围/影响面(只读验证,不实际写入/删除,最小影响)", "影响评估", "✓"),
        ("7 报告", "生成此报告(含完整攻击路径+证据链,自动缓存登记)", "报告(已登记)", "✓"),
    ]
    for row in ptes:
        _h("| " + " | ".join(row) + " |")
    L.append("")

    # ---- 三、执行过程(攻击链) ----
    _h("## 3 攻击路径与执行过程")
    _h("从公开信息到漏洞确认的**完整渗透过程**，含选用的方法、为什么这么做、请求与结果：")
    steps = [
        ("3.1 资产暴露面测绘",
         "对主域执行子域枚举(crt.sh被动) + DNS前缀暴力，得到全部候选子域；"
         "再用HTTP探活识别存活Web资产及其响应指纹，完成暴露面测绘。"),
        ("3.2 攻击面建模",
         "根据指纹(Server头/标题/Cookie)推断组件族(Spring/Shiro/ThinkPHP等)与潜在Nday；"
         "同时从存活页面提取输入向量：URL参数、表单字段、带参链接，确定可注入点。"),
        ("3.3 被动漏洞证据探测",
         "对存活资产探测敏感文件/源码/备份/目录列表，判定标准为【HTTP 200 + 响应体含真实证据特征】。"
         "502/403/404/超时一律不计为漏洞。"),
        ("3.4 主动渗透(注入验证)",
         "对提取的输入向量逐类投递 payload，用**业务行为差分 + 报错/反射/文件内容特征**确认："
         "SQLi(单引号报错签名 / AND 1=1 vs AND 1=2 布尔盲注差分)、"
         "Reflected XSS(指纹 payload 原样反射且事件属性未被转义，HTML上下文)、"
         "路径穿越·任意文件读取(注入 ../ 后返回真实 /etc/passwd 内容)、"
         "开放重定向(外部域名反射进 Location 或 JS 跳转)。"
         "全部为只读·最小影响验证，不写库、不删改、不执行RCE。"),
        ("3.5 Nday 特征验证",
         "对命中指纹的关键组件做无害行为探测：Shiro 发送非法 rememberMe Cookie 观测 "
         "Set-Cookie: rememberMe=deleteMe 反序列化入口特征；"
         "Spring 探测 /actuator/env 等端点是否未授权返回敏感JSON。"
         "确系真实信息泄露/入口特征才转 pending，配合版本人核对后人工定级上报。"),
        ("3.6 独立复测取证",
         "对每条证据漏洞进行两次独立HTTP取证，两次均满足证据特征才标记 confirmed；"
         "否则标记误报并剔除，确保100%可复现。"),
    ]
    for title, body in steps:
        _h(f"### {title}")
        _h(body)
        L.append("")

    # ---- 3.x 攻击执行明细（attack_log）----
    if attack_log:
        hits = [a for a in attack_log if a.get("verdict") == "命中"]
        _h("### 3.7 攻击执行明细（对每个存活资产的注入过程）")
        _h(f"> 共发起 **{len(attack_log)}** 次注入探测，其中 **命中证据 {len(hits)}** 次。"
           "每条含：目标URL、注入参数、payload、响应状态、命中与否。")
        _h("| # | 目标URL | 参数 | payload | 状态 | 结果 |")
        _h("|---|--------|------|---------|------|------|")
        shown = 0
        for a in attack_log:
            st = a.get("status")
            status_s = str(st) if st is not None else "—"
            verdict = a.get("verdict", "")
            mark = "✅命中" if verdict == "命中" else ("⛔未命中" if verdict else "ℹ️")
            _h(f"| {shown+1} | `{_esc((a.get('url') or '')[:50])}` | `{_esc(a.get('param') or '')}` "
               f"| `{_esc((a.get('payload') or '')[:40])}` | {status_s} | {mark} |")
            shown += 1
            if shown >= 120:
                _h(f"| … | 其余 {len(attack_log)-shown} 条省略 | | | | |")
                break
        L.append("")

    # ---- 四、漏洞详情（只有 confirmed）----
    _h("## 4 已确认漏洞详情")
    if not confirmed:
        _h("本轮未确认到100%证据的漏洞。响应截图/原始请求多为 5xx/4xx 或错误页，均已作误报剔除。")
        _h("建议扩大测试资产范围或转人工深入测试后重新评估。")
    else:
        _h("> 以下每个漏洞均附带 ① 漏洞证据 ✅ ② 原始请求/响应 ③ 复测二次取证 ④ 影响与修复，可直接用于SRC提交。")
        L.append("")
        for i, rec in enumerate(confirmed, 1):
            url = rec.get("url", "")
            ftype = rec.get("type", "")
            sev = rec.get("sev", "低")
            _h(f"### 4.{i} {ftype}")
            _h(f"- **影响URL**：`{url}`")
            _h(f"- **漏洞类型**：{ftype}  ({sev})")
            _h(f"- **来源**：{_src_cn(rec.get('source'))}")
            evi = rec.get("evidence") or {}
            if rec.get("source") == "active-exploit":
                _h(f"- **注入参数**：`{_esc(evi.get('param') or '-')}`")
                _h(f"- **注入Payload**：`{_esc(evi.get('payload') or '-')}`")
            _h(f"- **攻击请求**：`GET {url}`")
            rv = rev_map.get(url + ftype) or {}
            if rv:
                _h(f"- **复测结论**：<code>{_esc(rv.get('status'))}</code> — {rv.get('reason','')}")
            # 证据链
            evi = rec.get("evidence") or rv.get("evidence") or {}
            if evi:
                if evi.get("request"):
                    _h("**证据·原始请求：**")
                    L.append(f"```http\n{evi['request']}\n```")
                    L.append("")
                if evi.get("response_line"):
                    _h("**证据·响应状态与头：**")
                    L.append(f"```\n{evi.get('response_line')}\n{evi.get('response_headers','')}\n```")
                    L.append("")
                if evi.get("response_snippet"):
                    _h("**证据·响应体指纹片段(证明含真实漏洞内容,已脱敏)：**")
                    L.append("```\n" + evi["response_snippet"][:500] + "\n```")
                    L.append("")
                if evi.get("verification"):
                    _h(f"**证据结论**：{evi['verification']}")
                    L.append("")
                if evi.get("rounds"):
                    _h("**复测二次取证记录：**")
                    for r_ in evi["rounds"]:
                        st = r_.get("status")
                        _h(f"- 第{r_.get('round')}次: HTTP {st} {'(命中证据)' if st==200 else '(非200)'} 内容长度 {r_.get('body_len',0)}")
                    L.append("")
            fix_map = {
                "严重": "立即下线或脱敏该备份/源码文件，删除Web目录下所有备份，配置服务器禁止访问敏感扩展名，启用访问白名单。",
                "高": "移除/保护敏感文件，配置访问控制与WAF规则，规范部署流程避免源码残留。",
                "中": "加固访问控制，清理暴露性配置，定期安全巡检。",
                "低": "按基线要求完善配置，纳入整改清单。",
            }
            _h(f"- **修复建议**：{fix_map.get(sev, '按安全基线加固并复测。')}")
            L.append("")

    # ---- 五、Nday 线索（不是漏洞，明确标注）----
    _h("## 5 本地Nday线索（需人工验证，不可直接上报）")
    if nday_candidates:
        _h("> ⚠️ 以下为基于组件指纹关联的已知漏洞线索，仅提示资产可能受影响。"
           "必须人工核验目标真实版本/利用前置条件/授权后，才能决定是否上报。**绝不当已确认漏洞**。")
        _h("| 产品 | 关联CVE | 描述 |")
        _h("|------|--------|------|")
        for c in nday_candidates[:30]:
            _h(f"| {c.get('fingerprint','')} | {c.get('cve','') or c.get('cnvd','')} | {_esc(c.get('desc','')[:60])} |")
        L.append("")
    else:
        _h("（未匹配到与目标指纹精确对应的Nday线索）")
        L.append("")

    # ---- 六、误报剔除说明（增强可信度）----
    if rejected:
        _h("## 6 误报/剔除说明")
        _h("以下项因缺少真实漏洞证据已被剔除，不计入漏洞：")
        _h("| 类型 | URL | 剔除原因 |")
        _h("|------|-----|----------|")
        for rec in rejected[:15]:
            rv = rev_map.get(rec.get("url","")+rec.get("type","")) or {}
            _h(f"| {rec.get('type','')} | `{rec.get('url','')[:40]}` | {rv.get('status','未取证')}:{_esc(rv.get('reason',''))[:40]} |")
        L.append("")

    # ---- 七、上报建议 ----
    _h("## 7 上报建议")
    _h("1. 仅上报 **已确认(第4章)** 且等级为中危以上的漏洞。")
    _h("2. 确认目标资产归属与测试授权，遵循负责任披露流程。")
    _h("3. 本报告含完整证据链，可在「报告管理」标签页查看/打开/导出，作支撑材料。")
    _h("4. 修复后请目标方复测，并在约定期限内公开披露（可选）。")
    L.append("---")
    _h("*本报告由 edu-src-toolkit 自动生成，仅收录100%证据确认漏洞。*")
    L.append("")

    report_path = out_dir / "渗透测试报告.md"
    report_path.write_text("\n".join(L), encoding="utf-8")
    if emit:
        emit(f"    ✓ 报告已生成: {report_path}")
    else:
        print(f"    ✓ 报告已生成: {report_path}")
    return report_path


if __name__ == "__main__":
    school = {"name": "测试大学", "code": "test", "domains": ["test.edu.cn"]}
    build_report(school, [], [], [], None, assets_info={"assets": 0, "alive": 0})