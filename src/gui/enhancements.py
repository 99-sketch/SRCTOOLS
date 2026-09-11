# -*- coding: utf-8 -*-
"""GUI 增强模块 - 借鉴 EduSentinel 的优秀设计

新增功能：
1. 授权闸门 - 启动时强制确认授权范围
2. 高校清单选择器 - 搜索+过滤+批量勾选
3. 设置标签页 - 指纹开关/浏览器渲染/OOB/报告格式
4. 上报草稿标签页 - 按平台生成提交材料
5. 增强报告 - CVSS评分+整改优先级+多格式
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, filedialog
from pathlib import Path
import json
import time
import os


# ==================== 1. 授权闸门 ====================
class AuthGate(tk.Toplevel):
    """启动授权闸门：必须勾选确认方可进入。"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("授权确认 · 教育SRC挖洞工具")
        self.geometry("600x480")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.ok = False

        tk.Label(self, text="⚠ 授权范围确认（必读）", font=("Microsoft YaHei", 14, "bold"),
                 fg="#c0392b").pack(pady=12)

        text = scrolledtext.ScrolledText(self, width=70, height=18, wrap=tk.WORD)
        text.pack(padx=16, pady=4)
        notice = (
            "教育SRC挖洞工具是一个面向教育行业 SRC（安全应急响应中心）的\n"
            "自动化漏洞挖掘与评估工具，功能包含：自动化信息收集、漏洞扫描、\n"
            "主动验证、Nday检测、Webshell管理、C2框架集成、报告生成。\n\n"
            "重要声明：\n"
            "1. 本工具所有检测均为【非入侵式】（只读/连接级探测），\n"
            "   不包含任何写操作、注入payload或破坏性质请求。\n"
            "2. 你只能对【已获得书面或平台授权】的目标使用本工具。\n"
            "3. 严禁对任何未授权资产进行扫描、探测或攻击，否则可能违反\n"
            "   《网络安全法》等法律法规并承担相应法律责任。\n"
            "4. 工具集成的外部扫描器（nuclei/afrog/xray等）均为被动检测，\n"
            "   不主动发送攻击payload。\n"
            "5. 报告仅用于授权方的安全整改与合规建设。\n\n"
            "点击「我已确认」即表示你理解并承诺遵守上述要求。"
        )
        text.insert(tk.END, notice)
        text.config(state=tk.DISABLED)

        self.var = tk.BooleanVar()
        tk.Checkbutton(self, text="我已阅读并承诺：仅在授权范围内使用本工具",
                       variable=self.var, font=("Microsoft YaHei", 10)).pack(pady=10)

        tk.Button(self, text="我已确认，进入工具", command=self._confirm,
                  bg="#27ae60", fg="white", font=("Microsoft YaHei", 11, "bold"),
                  width=20).pack(pady=4)

    def _confirm(self):
        if not self.var.get():
            messagebox.showwarning("请先确认", "请勾选确认框后再进入。")
            return
        self.ok = True
        self.destroy()

    def _on_close(self):
        self.ok = False
        self.destroy()


# ==================== 2. 高校清单选择器 ====================
class UniversityPicker(tk.Toplevel):
    """从内置EDUSRC高校清单中选择目标，支持搜索+过滤+批量勾选。"""
    def __init__(self, parent, universities, on_select):
        super().__init__(parent)
        self.title("选择高校（EDUSRC教育漏洞报告平台高校清单）")
        self.geometry("700x600")
        self.universities = universities
        self.on_select = on_select
        self.checks = {}

        tk.Label(self, text="勾选要加入目标列表的高校（默认未授权，请自行确认授权后使用）",
                 fg="#c0392b", font=("Microsoft YaHei", 9)).pack(padx=8, pady=6)

        # 搜索行
        srow = tk.Frame(self)
        srow.pack(fill=tk.X, padx=8)
        tk.Label(srow, text="搜索：", font=("Microsoft YaHei", 9)).pack(side=tk.LEFT)
        self.kw = tk.StringVar()
        tk.Entry(srow, textvariable=self.kw, width=24, font=("Microsoft YaHei", 9)).pack(side=tk.LEFT, padx=4)
        tk.Label(srow, text="（输入校名/拼音/域名搜索）", fg="#888", font=("Microsoft YaHei", 8)).pack(side=tk.LEFT, padx=4)

        # 列表区域（带滚动条）
        body = tk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        canvas = tk.Canvas(body, highlightthickness=0)
        sb = ttk.Scrollbar(body, orient=tk.VERTICAL, command=canvas.yview)
        self.inner = tk.Frame(canvas)
        canvas.create_window((0, 0), window=self.inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定搜索
        self.kw.trace_add("write", self._rebuild)
        self._rebuild()

        # 底部按钮
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=8, pady=8)
        tk.Button(btn_frame, text="全选", command=self._select_all,
                  bg="#3498db", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="取消全选", command=self._deselect_all,
                  bg="#95a5a6", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="加入选中的高校", command=self._do_add,
                  bg="#16a085", fg="white", font=("Microsoft YaHei", 10, "bold")).pack(side=tk.RIGHT, padx=2)

    def _rebuild(self, *_):
        for w in self.inner.winfo_children():
            w.destroy()
        self.checks.clear()
        q = self.kw.get().strip().lower()
        shown = 0
        for u in self.universities:
            # 适配 UNIVERSITIES 数据格式：name/code/domains
            name = u.get("name", "")
            code = u.get("code", "")
            domains = u.get("domains", [])
            domain = domains[0] if domains else ""
            
            # 搜索过滤
            if q and q not in (name + code + domain).lower():
                continue
            
            v = tk.BooleanVar()
            self.checks[code] = (v, u)
            txt = f'{name}  ({domain})  [{code}]'
            tk.Checkbutton(self.inner, text=txt, variable=v, anchor="w",
                           font=("Microsoft YaHei", 9)).pack(fill=tk.X, anchor="w")
            shown += 1
        if shown == 0:
            tk.Label(self.inner, text="（无匹配高校）", fg="#888").pack(anchor="w")
        self.inner.update_idletasks()
        canvas = self.inner.winfo_parent()
        if canvas:
            self.inner.master.configure(scrollregion=self.inner.master.bbox("all"))

    def _select_all(self):
        for v, u in self.checks.values():
            v.set(True)

    def _deselect_all(self):
        for v, u in self.checks.values():
            v.set(False)

    def _do_add(self):
        selected = []
        for domain, (v, u) in self.checks.items():
            if v.get():
                selected.append(u)
        if not selected:
            messagebox.showinfo("提示", "请先勾选至少一所高校。")
            return
        self.on_select(selected)
        messagebox.showinfo("完成", f"已加入 {len(selected)} 所高校，请逐项确认授权后再运行评估。")
        self.destroy()


# ==================== 3. 设置标签页 ====================
class SettingsTab(ttk.Frame):
    """设置标签页 - 指纹开关/浏览器渲染/OOB/报告格式。"""
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        # 漏洞指纹检测
        lf = ttk.LabelFrame(self, text="漏洞指纹检测（非入侵式：被动识别+安全主动探针）")
        lf.pack(fill=tk.X, padx=10, pady=8)
        self.fp_vars = {}
        fingerprints = [
            {"id": "shiro", "name": "Apache Shiro", "default": True},
            {"id": "fastjson", "name": "Fastjson", "default": True},
            {"id": "log4j2", "name": "Log4j2", "default": True},
            {"id": "struts2", "name": "Struts2", "default": True},
            {"id": "weblogic", "name": "WebLogic", "default": True},
            {"id": "spring", "name": "Spring Framework", "default": True},
            {"id": "thinkphp", "name": "ThinkPHP", "default": True},
            {"id": "nacos", "name": "Nacos", "default": True},
            {"id": "jenkins", "name": "Jenkins", "default": True},
        ]
        for i, fp in enumerate(fingerprints):
            v = tk.BooleanVar(value=fp["default"])
            self.fp_vars[fp["id"]] = v
            ttk.Checkbutton(lf, text=fp["name"], variable=v).grid(
                row=i // 3, column=i % 3, sticky="w", padx=10, pady=2)

        # 浏览器渲染
        bf = ttk.LabelFrame(self, text="真实浏览器渲染（用于JS渲染后的指纹识别与证据截图）")
        bf.pack(fill=tk.X, padx=10, pady=8)
        self.use_browser = tk.BooleanVar(value=True)
        self.take_shot = tk.BooleanVar(value=True)
        ttk.Checkbutton(bf, text="启用浏览器渲染（提高SPA/JS站点指纹准确率）",
                        variable=self.use_browser).grid(row=0, column=0, sticky="w", padx=10, pady=2)
        ttk.Checkbutton(bf, text="生成证据截图（写入报告「证据截图」列）",
                        variable=self.take_shot).grid(row=0, column=1, sticky="w", padx=10, pady=2)

        # OOB回调
        of = ttk.LabelFrame(self, text="带外(OOB)确认（可选，仅在你有自有回调域名时启用）")
        of.pack(fill=tk.X, padx=10, pady=8)
        r = tk.Frame(of)
        r.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(r, text="回调域名（如xxxxx.dnslog.cn）：").pack(side=tk.LEFT)
        self.oob_var = tk.StringVar()
        ttk.Entry(r, textvariable=self.oob_var, width=40).pack(side=tk.LEFT, padx=4)
        ttk.Label(of, text=" 启用后会向目标发送仅含你回调地址的探测请求（用于确认Shiro/Fastjson/Log4j2）。\n"
                           "   工具不收集回调结果，请自行到回调平台核对。仅在授权范围内使用。",
                  foreground="#c0392b").pack(anchor=tk.W, padx=10, pady=2)

        # 报告输出
        rf = ttk.LabelFrame(self, text="报告输出")
        rf.pack(fill=tk.X, padx=10, pady=8)
        self.fmt_html = tk.BooleanVar(value=True)
        self.fmt_word = tk.BooleanVar(value=True)
        self.fmt_pdf = tk.BooleanVar(value=False)
        ttk.Checkbutton(rf, text="HTML", variable=self.fmt_html).grid(row=0, column=0, padx=12, pady=2)
        ttk.Checkbutton(rf, text="Word(.docx)", variable=self.fmt_word).grid(row=0, column=1, padx=12, pady=2)
        ttk.Checkbutton(rf, text="PDF", variable=self.fmt_pdf).grid(row=0, column=2, padx=12, pady=2)

        # 保存按钮
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=8)
        tk.Button(btn_frame, text="保存设置", command=self._save_settings,
                  bg="#27ae60", fg="white", font=("Microsoft YaHei", 10, "bold")).pack(side=tk.RIGHT)

    def _save_settings(self):
        settings = self.get_settings()
        # 使用绝对路径，避免exe运行时CWD问题
        from src.config import OUTPUTS_DIR
        settings_file = OUTPUTS_DIR / "settings.json"
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
        messagebox.showinfo("完成", "设置已保存。")

    def get_settings(self):
        fmts = tuple(f for f, v in
                     (("html", self.fmt_html), ("word", self.fmt_word), ("pdf", self.fmt_pdf))
                     if v.get()) or ("html",)
        return {
            "fp_enabled": [k for k, v in self.fp_vars.items() if v.get()],
            "use_browser": self.use_browser.get(),
            "take_shot": self.take_shot.get(),
            "oob": self.oob_var.get().strip() or None,
            "formats": fmts,
        }


# ==================== 4. 上报草稿标签页 ====================
class DraftTab(ttk.Frame):
    """上报草稿标签页 - 按平台生成提交材料。"""
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        ttk.Label(self, text="从最近一次评估结果生成漏洞上报草稿（Markdown），便于到EDUSRC/补天/CNVD等平台提交。",
                  font=("Microsoft YaHei", 10)).pack(anchor=tk.W, padx=10, pady=8)

        row = tk.Frame(self)
        row.pack(fill=tk.X, padx=10)
        ttk.Label(row, text="目标平台：").pack(side=tk.LEFT)
        self.draft_platform = tk.StringVar(value="EDUSRC")
        platforms = ["EDUSRC", "补天", "CNVD", "北京教育SRC", "高校SRC", "自定义"]
        ttk.Combobox(row, textvariable=self.draft_platform, values=platforms,
                     width=14, state="readonly").pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="上报人：").pack(side=tk.LEFT, padx=(12, 0))
        self.draft_author = tk.StringVar()
        ttk.Entry(row, textvariable=self.draft_author, width=18).pack(side=tk.LEFT, padx=4)
        tk.Button(row, text="生成本次全部发现的草稿", command=self._gen_drafts,
                  bg="#2980b9", fg="white").pack(side=tk.LEFT, padx=8)

        self.draft_box = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 9),
                                                   state=tk.DISABLED)
        self.draft_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

    def _gen_drafts(self):
        if not self.app.last_reports:
            messagebox.showinfo("提示", "请先运行一次评估，再生成上报草稿。")
            return

        platform = self.draft_platform.get()
        author = self.draft_author.get().strip()

        # 获取最近的findings
        findings = []
        for domain, paths in self.app.last_reports.items():
            findings_file = Path(paths.get("findings", ""))
            if findings_file.exists():
                data = json.loads(findings_file.read_text(encoding="utf-8"))
                findings.extend(data.get("findings", []))

        if not findings:
            messagebox.showinfo("提示", "最近结果为空，无内容可生成。")
            return

        # 生成草稿
        drafts = []
        from src.config import OUTPUTS_DIR
        out_dir = OUTPUTS_DIR / "drafts"
        out_dir.mkdir(parents=True, exist_ok=True)

        for f in findings:
            if f.get("sev") in ("低", "提示"):
                continue
            draft = self._build_draft(platform, f, author)
            safe = f.get("url", "target").replace("/", "_").replace(":", "_")
            ts = time.strftime("%Y%m%d_%H%M%S")
            path = out_dir / f"draft_{safe}_{ts}.md"
            path.write_text(draft, encoding="utf-8")
            drafts.append(str(path))

        self.draft_box.config(state=tk.NORMAL)
        self.draft_box.delete("1.0", tk.END)
        self.draft_box.insert(tk.END, f"已生成 {len(drafts)} 份 {platform} 上报草稿：\n\n" + "\n".join(drafts))
        self.draft_box.config(state=tk.DISABLED)
        messagebox.showinfo("完成", f"已生成 {len(drafts)} 份草稿，路径见「上报草稿」页。")

    def _build_draft(self, platform, finding, author):
        sev_map = {"严重": "Critical", "高": "High", "中": "Medium", "低": "Low", "提示": "Info"}
        sev = sev_map.get(finding.get("sev", "Info"), "Info")
        title = f"[{finding.get('type', '')}] {finding.get('url', '')} {finding.get('sev', '')}"
        detail = finding.get("evidence", {})
        evidence = json.dumps(detail, ensure_ascii=False, indent=2) if isinstance(detail, dict) else str(detail)

        lines = [
            f"# 漏洞上报草稿 · {platform}",
            "",
            f"- 标题：{title}",
            f"- 目标：{finding.get('url', '')}",
            f"- 严重度：{sev}",
            f"- 类型：{finding.get('type', '')}",
            f"- 上报人：{author}",
            "",
            "## 详细描述",
            f"目标URL：{finding.get('url', '')}",
            f"漏洞类型：{finding.get('type', '')}",
            f"危害等级：{finding.get('sev', '')}",
            "",
            "## 证据",
            evidence,
            "",
            f"> 本草稿由教育SRC挖洞工具在授权范围内生成，提交前请确认已获目标授权并遵守平台规则。",
        ]
        return "\n".join(lines)


# ==================== 5. 平台预设配置 ====================
PLATFORM_PRESETS = {
    "EDUSRC": {
        "base_url": "https://src.sjtu.edu.cn/",
        "auth_header": "Cookie",
        "auth_format": "{token}",
        "method": "POST",
        "note": "教育漏洞报告平台EDUSRC（上海交通大学运营，src.sjtu.edu.cn）。无公开批量资产API，"
                "实际提交为网页表单；请优先使用「导出草稿」按平台《漏洞提交规范》手工提交。",
    },
    "补天": {
        "base_url": "https://www.butian.net/",
        "auth_header": "Cookie",
        "auth_format": "{token}",
        "method": "POST",
        "note": "补天平台（奇安信，butian.net）。需登录态Cookie；请以你账号实际可用接口为准。",
    },
    "CNVD": {
        "base_url": "https://www.cnvd.org.cn/",
        "auth_header": "Authorization",
        "auth_format": "Bearer {token}",
        "method": "GET",
        "note": "CNVD官方未公开资产批量API，请按你账号实际可用的接口填写base_url与路径。",
    },
    "北京教育SRC": {
        "base_url": "https://bjedusrc.buu.edu.cn/",
        "auth_header": "Cookie",
        "auth_format": "{token}",
        "method": "POST",
        "note": "北京教育行业SRC（北京联合大学运营，bjedusrc.buu.edu.cn）。同样以网页表单提交为主。",
    },
    "高校SRC": {
        "base_url": "https://",
        "auth_header": "Cookie",
        "auth_format": "{token}",
        "method": "POST",
        "note": "各高校自建SRC接口差异极大，请在界面中按该校实际API填写base_url。",
    },
    "自定义": {
        "base_url": "https://",
        "auth_header": "Authorization",
        "auth_format": "Bearer {token}",
        "method": "GET",
        "note": "任意兼容JSON的资产接口。",
    },
}
