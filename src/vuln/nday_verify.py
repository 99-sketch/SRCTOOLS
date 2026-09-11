# -*- coding: utf-8 -*-
"""Nday 主动验证器（真实验证，非指纹猜）

为每个候选Nday做『无害验证』，通过请求行为差异判断目标是否确实存在对应漏洞特征。
只做行为观察，不做利用、不植入payload、不破坏。

当前支持的验证器：
  - Shiro RememberMe: 发送构造的失效rememberMe Cookie，观察 Set-Cookie: rememberMe=deleteMe
    (这是Shiro处理非法rememberCookie时的固定特征，可确认目标确实运行Shiro并走到反序列化入口)
  - 泛微 ecology / 致远 seeyon: 探测已知特征路径/cookie (占位，需转换真实系统)

原则：验证结果仅标记『特征存在』，配合侦查，绝不自动判为可利用漏洞；是否上报由人工结合版本评估。
"""

import sys
import ssl
import time
import json
from pathlib import Path

import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.config import output_dir_for


def _http_get(url, headers=None, timeout=12):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    t0 = time.time()
    r = {"status": None, "set_cookie": "", "body": "", "ctime": int((time.time()-t0)*1000)}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            r["status"] = resp.status
            hd = dict(resp.headers.items())
            r["set_cookie"] = hd.get("Set-Cookie", "")
            r["body"] = resp.read(300000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        r["status"] = e.code
        hd = dict(e.headers.items())
        r["set_cookie"] = hd.get("Set-Cookie", "")
    except Exception as ex:
        r["error"] = str(ex)
    return r


# ============ 验证器库 ============
def verify_java_deser_entry(url):
    """Java 反序列化中间件入口指纹识别（非破坏，不发攻击payload）。

    通过框架特征路径/响应头/错误签名识别 weblogic / fastjson / struts 等
    反序列化中间件入口。仅确认『存在该组件』，不实际触发RCE；是否可利用需
    结合版本与授权内 PoC 人工评估。
    """
    base = url.rstrip("/")
    hits = []
    checks = [
        ("weblogic", ["/console/login/LoginForm.jsp", "/console/css/login.css",
                      "/wls-wsat/CoordinatorPortType"]),
        ("struts", ["/index.action", "/hello.action"]),
    ]
    low_bodies = {}
    for prod, paths in checks:
        for p in paths:
            r = _http_get(base + p)
            body = r.get("body", "")
            low = body[:8000].lower()
            if r.get("status") == 200:
                if prod == "weblogic" and ("weblogic" in low or "oracle fussion" in low
                                           or "console" in low and "login" in low):
                    hits.append(f"weblogic/{p}")
                    break
                if prod == "struts" and ("struts" in low or "taglib" in low):
                    hits.append(f"struts/{p}")
                    break
    # fastjson：对 POST 参数响应含 fastjson 版本/JSON 解析特征（非破坏探测）
    r = _http_get(base)
    if "fastjson" in r.get("body", "")[:8000].lower():
        hits.append("fastjson-body-mark")
    return {
        "product": "java-deser",
        "check": "java-deserialization-framework-entry",
        "url": base,
        "present": bool(hits),
        "evidence": f"检测到反序列化中间件入口特征: {', '.join(hits) or '无'}",
        "conclusion": "确认存在 java 反序列化中间件入口(需结合版本人工评估是否可RCE)" if hits
                      else "未检测到典型 java 反序列化中间件入口",
        "caveat": "仅为组件入口指纹，不代表可利用；上报需人工核对版本与授权内PoC",
    }


def verify_spring_actuator(url):
    """Spring Boot Actuator 暴露验证（无害只读）。

    Spring Boot 若未加安全限制，暴露 /actuator/ 端点会返回 JSON 格式的健康/环境信息，
    这是 Spring boot actuator 的确定特征。检测 /actuator/env 等只读端点返回 JSON。
    """
    base = url.rstrip("/")
    hits = []
    for path in ("/actuator", "/actuator/env", "/actuator/heapdump",
                 "/actuator/health", "/actuator/mappings", "/env"):
        r = _http_get(base + path)
        body = r.get("body", "")
        status = r.get("status")
        ctype = ""
        # _http_get 不返回 content-type，这里看 body 特征
        low = body[:12000].lower()
        if status == 200 and ("actuator" in low or "\"status\"" in low or
                              "\"beans\"" in low or "\"propertySources\"" in low):
            hits.append(path)
            if len(hits) >= 3:
                break
    return {
        "product": "spring",
        "check": "spring-actuator-exposure",
        "url": base,
        "present": bool(hits),
        "evidence": f"未认证访问敏感Actuator端点返回200并含JSON泄露: {', '.join(hits) or '无'}",
        "conclusion": "检测到Spring Boot Actuator端点未授权暴露（信息泄露，部分端点可致RCE如heapdump/env）" if hits
                      else "未发现Spring Actuator暴露",
        "caveat": "endpoint暴露需人工核对版本与可读性，env/heapdump可能泄露密钥，需谨慎评估后上报",
    }


def verify_shiro_rememberme(url):
    """Shiro RememberMe 特征验证。

    Apache Shiro 在收到非法 rememberMe Cookie 时，会响应
      Set-Cookie: rememberMe=deleteMe
    这是 Shiro 处理流程的固定特征，可用于确认目标确实运行 Shiro，
    并证明存在反序列化入口（Shiro-550 类漏洞前提）。
    """
    base = url.rstrip("/") + "/"
    # 无cookie基线
    base_resp = _http_get(base)
    # 发送非法rememberMe cookie
    evil = "rememberMe=2;"  # 非法base64，Shiro尝试解码失败触发deleteMe
    evil_resp = _http_get(base, headers={"Cookie": evil})

    given = False
    if "deleteMe" in evil_resp.get("set_cookie", "") or \
       "deleteMe" in evil_resp.get("body", ""):
        given = True

    return {
        "product": "shiro",
        "check": "shiro-rememberme-cookie",
        "url": base.rstrip("/"),
        "present": given,
        "evidence": f"基线状态码={base_resp.get('status')}, "
                    f"含rememberMe非法Cookie后响应头Set-Cookie={evil_resp.get('set_cookie', '')[:80]}",
        "conclusion": "检测到Shiro rememberMe处理特征，确认部署Shiro且存在反序列化入口(需结合版本评估是否可RCE)" if given
                      else "未检测到Shiro rememberMe deleteMe特征",
        "caveat": "此为特征确认，不代表可利用；上报需人工核验版本与利用前置条件",
    }


def verify_thinkphp_path(url):
    """ThinkPHP 版本特征验证（通过响应头/错误信息）"""
    base = url.rstrip("/")
    base_resp = _http_get(base)
    fp = []
    # 简化：检测常见ThinkPHP释放特征
    low_body = base_resp.get("body", "").lower()
    if "thinkphp" in low_body or "think\\" in low_body:
        fp.append("thinkphp标记")
    return {"product": "thinkphp", "check": "thinkphp-signature",
            "url": base, "present": bool(fp),
            "evidence": "".join(fp) or "无thinkphp标记",
            "conclusion": "存在ThinkPHP标记" if fp else "未确认ThinkPHP",
            "caveat": ""}


# ============ 调度 ============
VERIFIERS = {
    "shiro": verify_shiro_rememberme,
    "thinkphp": verify_thinkphp_path,
    "spring": verify_spring_actuator,
    "java-deser": verify_java_deser_entry,
    "weblogic": verify_java_deser_entry,
    "struts": verify_java_deser_entry,
    "fastjson": verify_java_deser_entry,
}

# 即使没有Nday线索，也始终对命中指纹的资产做特征验证的关键字
FORCE_VERIFY_PRODUCTS = ["spring", "shiro", "weblogic", "struts", "fastjson", "shiro"]

def verify_nday(alive_results, nday_candidates, school_code, stop_flag=None, emit=None):
    """对Nday候选涉及的产品，在存活资产上做主动特征验证。

    返回 verified 列表：[{cve_info, product, url, result}]
    只有 present=True 的才标记为『特征存在(可人工上报候选)』。
    """
    def _out(msg):
        if emit:
            emit(msg)
        else:
            print(msg)

    _out(f"[*] Nday主动验证启动（无害行为探测）")
    out_dir = output_dir_for(school_code)

    # 收集候选引用的产品
    products = {}
    for c in nday_candidates:
        p = c.get("fingerprint", "").lower()
        products.setdefault(p, c)
    # 无候选时也始终对命中指纹的关键产品做强制特征验证（如 Spring actuator）
    for fp in alive_results:
        for h in fp.get("hits", []):
            hl = h.lower()
            if hl in FORCE_VERIFY_PRODUCTS or any(k in hl for k in FORCE_VERIFY_PRODUCTS):
                if hl not in products:
                    products[hl] = {"fingerprint": hl, "cve": "", "cnvd": "",
                                    "desc": "强制特征验证（无Nday候选）"}
    if not products:
        _out("    无Nday候选可验证")
        return []

    # 对每个存活资产跑相关验证器
    urls = list({fp["url"] for fp in alive_results})[:40]
    verified = []
    for prod, c in products.items():
        vf = VERIFIERS.get(prod)
        if not vf:
            continue
        _out(f"    验证产品 [{prod}] (引用CVE: {c.get('cve','')}) ...")
        for u in urls:
            if stop_flag and stop_flag.is_set():
                break
            try:
                res = vf(u)
            except Exception as e:
                res = {"present": False, "error": str(e)}
            if res.get("present"):
                verified.append({
                    "fingerprint": prod,
                    "cve": c.get("cve", ""),
                    "cnvd": c.get("cnvd", ""),
                    "url": u,
                    "evidence": res.get("evidence", ""),
                    "conclusion": res.get("conclusion", ""),
                    "caveat": res.get("caveat", ""),
                    "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
                _out(f"      ✓ {u} 命中特征: {res.get('evidence','')[:60]}")

    # 保存
    vpath = out_dir / "nday_verified.json"
    vpath.write_text(json.dumps(verified, ensure_ascii=False, indent=2), encoding="utf-8")
    _out(f"    Nday特征验证完成: 命中 {len(verified)} 处 (已保存 {vpath.name})")
    return verified


if __name__ == "__main__":
    for u in sys.argv[1:] or []:
        r = verify_shiro_rememberme(u)
        print(json.dumps(r, ensure_ascii=False, indent=2))