# -*- coding: utf-8 -*-
"""
教育SRC挖洞工具 - 可视化GUI版
基于 tkinter/ttk，后台线程执行，界面实时刷新。
打包：python -m PyInstaller --noconfirm edu_src_gui.spec
"""
import sys
import os
import ssl
import json
import queue
import threading
import traceback
from pathlib import Path

# ---- Windows 控制台/编码兜底（避免中文乱码）----
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

# 固定把项目根加入搜索路径（源码与exe(frozen)均适用）
if getattr(sys, "frozen", False):
    _RUN_ROOT = Path(r"e:\trae自动化\edu-src-toolkit")
else:
    _RUN_ROOT = Path(__file__).resolve().parent
for _p in (str(_RUN_ROOT), str(_RUN_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# ---- 内部模块 ----
from data.universities import UNIVERSITIES, get, search
from src.config import BASE_DIR, OUTPUTS_DIR, LOCAL_CVE_PATHS, which, output_dir_for
from src.report.manager import default_manager

REPORT_MGR = default_manager()


# =====================================================================
#  后台任务：把耗时的流水线放在线程里，通过 queue 回传事件
# =====================================================================
class Pipeline:
    """封装一次选校后的完整流程，支持分阶段执行。"""

    def __init__(self, school, emit):
        self.school = school          # dict
        self.emit = emit              # 回调: emit(日志/事件)
        self.stop_flag = threading.Event()
        self.subdomains = []
        self.alive = []
        self.findings = []
        self.nday = []
        self.reverify_out = None

    def _log(self, msg, kind="info"):
        self.emit({"type": "log", "msg": str(msg), "kind": kind})

    def stop(self):
        self.stop_flag.set()

    def _check_stop(self):
        return self.stop_flag.is_set()

    # ---------- 1. 资产收集 ----------
    def run_recon(self):
        from src.recon.asset_collector import collect_assets
        from src.recon.prober import probe_assets
        self._log(f"== 开始资产收集：{self.school['name']} ==")
        self.emit({"type": "state", "stage": "资产收集", "running": True})
        try:
            subdomains = collect_assets(self.school, use_external=True,
                                        stop_flag=self.stop_flag, emit=self._log)
            self.subdomains = subdomains
            self.emit({"type": "subdomains", "data": subdomains})
            if self._check_stop():
                return
            self._log("== 子域收集完成，开始探活指纹 ==")
            alive = probe_assets(subdomains, self.school["code"],
                                 stop_flag=self.stop_flag, emit=self._log)
            self.alive = alive
            self.emit({"type": "alive", "data": alive})
            self._log(f"== 资产收集完成：子域 {len(subdomains)} 条，存活 {len(alive)} 个 ==")
        except Exception as e:
            self._log(f"资产收集出错：{e}\n{traceback.format_exc()}", "error")
        finally:
            self.emit({"type": "state", "stage": "资产收集", "running": False})

    # ---------- 2. 漏洞挖掘 ----------
    def run_vuln(self):
        from src.vuln.engine import run_vuln_engine
        self._log(f"== 漏洞挖掘：{self.school['name']} ==")
        self.emit({"type": "state", "stage": "漏洞挖掘", "running": True})
        try:
            if not self.alive:
                self._log("无线索（未探活或探活为空），先执行资产收集。", "warn")
                return
            # 引擎内部三阶段：被动敏感泄露 + 主动注入(SQLi/XSS/穿越/重定向) + Nday特征验证
            findings, nday = run_vuln_engine(self.alive, self.school["code"],
                                             do_sensitive=True, stop_flag=self.stop_flag, emit=self._log)
            self.findings = findings
            self.nday = nday
            self.emit({"type": "findings", "data": findings})
            self.emit({"type": "nday", "data": nday})
            from collections import Counter
            src = Counter(f.get("source", "other") for f in findings)
            self._log(f"== 漏洞挖掘完成：确认 {len(findings)} 条 ==")
            self._log(f"    被动泄露 {src.get('sensitive-disclosure', 0)} 条 | "
                      f"主动注入 {src.get('active-exploit', 0)} 条 | "
                      f"Nday特征 {src.get('nday-active-verify', 0)} 条")
        except Exception as e:
            self._log(f"漏洞挖掘出错：{e}\n{traceback.format_exc()}", "error")
        finally:
            self.emit({"type": "state", "stage": "漏洞挖掘", "running": False})

    # ---------- 3. 复测 ----------
    def run_reverify(self):
        from src.reverify import reverify
        self._log(f"== 开始复测：{self.school['code']} ==")
        self.emit({"type": "state", "stage": "复测", "running": True})
        try:
            out = reverify(self.school["code"], stop_flag=self.stop_flag, emit=self._log)
            self.reverify_out = out
            self.emit({"type": "reverify", "data": out})
            sm = out.get("summary", {})
            self._log(f"== 复测完成：确认{sm.get('confirmed',0)} / 误报{sm.get('false_positive',0)} / 不可达{sm.get('unreachable',0)} ==")
        except Exception as e:
            self._log(f"复测出错：{e}\n{traceback.format_exc()}", "error")
        finally:
            self.emit({"type": "state", "stage": "复测", "running": False})

    # ---------- 4. 报告 ----------
    def run_report(self):
        from src.report.generator import build_report
        from src.vuln.poc_index import index_exploitarium
        self._log(f"== 生成报告：{self.school['name']} ==")
        try:
            ps = index_exploitarium()
            rp = build_report(self.school, self.alive, self.findings, self.nday,
                              reverify_out=self.reverify_out, poc_hits=ps,
                              assets_info={"assets": len(self.subdomains),
                                           "alive": len(self.alive)}, emit=self._log)
            self.emit({"type": "report", "path": str(rp)})
            self._log(f"报告已生成：{rp}")
            self.register_report(rp)
        except Exception as e:
            self._log(f"报告生成出错：{e}\n{traceback.format_exc()}", "error")

    # ---------- 5. 报告缓存登记（增删改查由「报告管理」标签页完成）----------
    def register_report(self, rp):
        try:
            from src.report.manager import default_manager
            rec = default_manager().register(rp, self.school,
                                             summary={"confirmed_vulns": len(self.findings)})
            self.emit({"type": "report_registered", "id": rec and rec.get("id")})
        except Exception as e:
            self._log(f"报告登记失败：{e}", "warn")

    # ---------- 全流程 ----------
    def run_full(self):
        from src.report.generator import build_report
        from src.vuln.poc_index import index_exploitarium
        self._log(f"===== 一键全流程启动：{self.school['name']} =====")
        try:
            self.run_recon()
            if self._check_stop():
                return
            self.run_vuln()
            if self._check_stop():
                return
            self.run_reverify()
            if self._check_stop():
                return
            # 报告
            ps = index_exploitarium()
            rp = build_report(self.school, self.alive, self.findings, self.nday,
                              reverify_out=self.reverify_out, poc_hits=ps,
                              assets_info={"assets": len(self.subdomains),
                                           "alive": len(self.alive)}, emit=self._log)
            self.emit({"type": "report", "path": str(rp)})
            self._log(f"报告已生成：{rp}")
            self.register_report(rp)
            self._log("===== 一键全流程完成 =====")
        except Exception as e:
            self._log(f"全流程出错：{e}\n{traceback.format_exc()}", "error")


# =====================================================================
#  GUI 主窗口
# =====================================================================
class EduSrcGUI:
    def __init__(self, root):
        self.root = root
        root.title("教育SRC挖洞工具")
        root.geometry("1080x720")
        root.minsize(960, 640)

        # 主题与样式
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass
        style.configure("TButton", padding=6, font=("Microsoft YaHei UI", 10))
        style.configure("TLabelframe.Label", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("Treeview", rowheight=24, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))

        # 运行时状态
        self.pipeline = None
        self.current_school = None
        self.events = queue.Queue()
        self._stages = {}          # stage -> (running, worker线程)
        self.report_mgr = REPORT_MGR

        self._build_layout()
        self._seed_tools()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # 定时拉取后台事件
        self.root.after(120, self._drain_events)

    # ---------------- 工具自检 ----------------
    def _seed_tools(self):
        try:
            cve_ok = Path(LOCAL_CVE_PATHS.get("cve_root", "")).exists()
            poc_ok = Path(LOCAL_CVE_PATHS.get("exploitarium", "")).exists()
            sub = which("subfinder")
            self._append_log(f"本地CVE库(D:\\CVE): {'✓ 可用' if cve_ok else '✗ 未找到'}")
            self._append_log(f"本地PoC库(D:\\漏洞库\\exploitarium): {'✓ 可用' if poc_ok else '✗ 未找到'}")
            self._append_log(f"外部工具 subfinder: {'✓ 已装' if sub else '✗ 未装(自动降级)'}")
        except Exception:
            pass

    # ---------------- 布局 ----------------
    def _build_layout(self):
        # 顶部：标题
        title = tk.Label(self.root, text="教育SRC挖洞工具  ·  公益安全研究",
                         font=("Microsoft YaHei UI", 15, "bold"),
                         fg="#ffffff", bg="#2b579a", pady=10)
        title.pack(fill="x")

        # 主工具栏（选校）
        tool = ttk.Frame(self.root, padding=8)
        tool.pack(fill="x")
        ttk.Label(tool, text="目标学校：", font=("Microsoft YaHei UI", 10)).pack(side="left")
        self.school_search = ttk.Entry(tool, width=22, font=("Microsoft YaHei UI", 10))
        self.school_search.pack(side="left", padx=4)
        self.school_search.bind("<Return>", lambda e: self._do_search())
        ttk.Button(tool, text="搜索", command=self._do_search).pack(side="left", padx=2)
        ttk.Button(tool, text="全列表", command=self._show_all_schools).pack(side="left", padx=2)

        self.school_box = ttk.Combobox(tool, width=34, font=("Microsoft YaHei UI", 10), state="readonly")
        self.school_box.pack(side="left", padx=6)
        ttk.Button(tool, text="选择此校", command=self._select_school).pack(side="left", padx=2)

        # 当前选择信息
        self.sel_label = ttk.Label(tool, text="未选择学校", foreground="#666",
                                   font=("Microsoft YaHei UI", 10))
        self.sel_label.pack(side="left", padx=12)

        # 流程按钮区
        ops = ttk.Frame(self.root, padding=(8, 0, 8, 6))
        ops.pack(fill="x")
        self.btn_recon = ttk.Button(ops, text="1 资产收集", command=self._start_recon)
        self.btn_vuln = ttk.Button(ops, text="2 漏洞挖掘", command=self._start_vuln)
        self.btn_verify = ttk.Button(ops, text="3 复测", command=self._start_reverify)
        self.btn_report = ttk.Button(ops, text="4 生成报告", command=self._start_report)
        self.btn_full = ttk.Button(ops, text="▶ 一键全流程", command=self._start_full)
        self.btn_stop = ttk.Button(ops, text="■ 停止", command=self._stop_all)
        for b in (self.btn_recon, self.btn_vuln, self.btn_verify, self.btn_report,
                  self.btn_full, self.btn_stop):
            b.pack(side="left", padx=3)

        # 进度条
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=8)
        self.stage_label = ttk.Label(self.root, text="空闲", foreground="#2b579a")
        self.stage_label.pack(anchor="w", padx=8)

        # 主内容：Notebook 多标签
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=6)

        self._build_assets_tab()
        self._build_findings_tab()
        self._build_nday_tab()
        self._build_log_tab()
        self._build_report_tab()
        self._build_webshell_tab()

    # ---- 资产标签页 ----
    def _build_assets_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 资产 (子域/存活) ")
        paned = ttk.Panedwindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=2, pady=2)

        # 左：子域名
        lf = ttk.LabelFrame(paned, text=" 子域名清单 ")
        self.tree_subs = ttk.Treeview(lf, columns=("sub",), show="headings")
        self.tree_subs.heading("sub", text="域名")
        self.tree_subs.column("sub", width=280)
        sb = ttk.Scrollbar(lf, command=self.tree_subs.yview)
        self.tree_subs.configure(yscrollcommand=sb.set)
        self.tree_subs.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        paned.add(lf, weight=1)

        # 右：存活资产
        rf = ttk.LabelFrame(paned, text=" 存活Web资产 + 指纹 ")
        self.tree_alive = ttk.Treeview(rf, columns=("url", "status", "title", "tech"),
                                       show="headings")
        for col, txt, w in (("url", "URL", 260), ("status", "代码", 50),
                            ("title", "标题", 160), ("tech", "指纹", 120)):
            self.tree_alive.heading(col, text=txt)
            self.tree_alive.column(col, width=w, anchor="w")
        sb2 = ttk.Scrollbar(rf, command=self.tree_alive.yview)
        self.tree_alive.configure(yscrollcommand=sb2.set)
        self.tree_alive.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")
        paned.add(rf, weight=2)

    # ---- 漏洞标签页 ----
    def _build_findings_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 漏洞发现 ")
        ff = ttk.LabelFrame(tab, text=" 检出漏洞 (含复测状态) ")
        ff.pack(fill="both", expand=True, padx=2, pady=2)
        self.tree_find = ttk.Treeview(ff, columns=("url", "type", "sev", "verify"),
                                      show="headings")
        for col, txt, w in (("url", "URL", 360), ("type", "类型", 200),
                            ("sev", "等级", 70), ("verify", "复测", 140)):
            self.tree_find.heading(col, text=txt)
            self.tree_find.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(ff, command=self.tree_find.yview)
        self.tree_find.configure(yscrollcommand=sb.set)
        self.tree_find.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        # Nday提示区
        self.nday_label = ttk.Label(tab, text="Nday候选：0", foreground="#a33")
        self.nday_label.pack(anchor="w", padx=6, pady=2)

    # ---- Nday标签页 ----
    def _build_nday_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Nday线索 ")
        self.tree_nday = ttk.Treeview(tab, columns=("fp", "kw", "cve", "desc"),
                                      show="headings")
        for col, txt, w in (("fp", "指纹", 90), ("kw", "关键词", 140),
                            ("cve", "CVE/CNVD", 120), ("desc", "描述", 300)):
            self.tree_nday.heading(col, text=txt)
            self.tree_nday.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(tab, command=self.tree_nday.yview)
        self.tree_nday.configure(yscrollcommand=sb.set)
        self.tree_nday.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    # ---- 日志标签页 ----
    def _build_log_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 运行日志 ")
        self.log_text = tk.Text(tab, wrap="none", height=10,
                                font=("Consolas", 9), state="disabled",
                                bg="#1e1e1e", fg="#dcdcdc")
        sb = ttk.Scrollbar(tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self._append_log("程序已启动，请先选择目标学校。", "ok")

    # ---- 报告管理标签页（缓存 + 增删改查 + 打开/查看）----
    def _build_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" 报告管理 ")

        bar = ttk.Frame(tab, padding=4)
        bar.pack(fill="x")
        ttk.Button(bar, text="↻ 刷新缓存", command=self._refresh_report_tab).pack(side="left", padx=2)
        ttk.Button(bar, text="🔍 查看内容", command=self._report_view).pack(side="left", padx=2)
        ttk.Button(bar, text="📂 打开报告", command=self._report_open).pack(side="left", padx=2)
        ttk.Button(bar, text="✎ 重命名", command=self._report_rename).pack(side="left", padx=2)
        ttk.Button(bar, text="🗑 删除(缓存)", command=self._report_delete).pack(side="left", padx=2)
        ttk.Label(bar, text="(删除仅移除缓存副本，不影响原始报告)", foreground="#888",
                  font=("Microsoft YaHei UI", 9)).pack(side="left", padx=8)

        wrap = ttk.Frame(tab)
        wrap.pack(fill="both", expand=True, padx=2, pady=2)
        self.tree_report = ttk.Treeview(
            wrap, columns=("title", "school", "created", "sev", "path"), show="headings")
        for col, txt, w in (("title", "标题", 200), ("school", "学校", 140),
                            ("created", "生成时间", 140), ("sev", "漏洞数", 70),
                            ("path", "路径", 300)):
            self.tree_report.heading(col, text=txt)
            self.tree_report.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(wrap, command=self.tree_report.yview)
        self.tree_report.configure(yscrollcommand=sb.set)
        self.tree_report.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree_report.bind("<Double-1>", lambda e: self._report_view())
        self.tree_report.bind("<Return>", lambda e: self._report_view())

        status = ttk.Label(tab, text="", foreground="#2b579a",
                           font=("Microsoft YaHei UI", 9))
        status.pack(anchor="w", padx=6, pady=2)
        self.report_status_label = status
        self._refresh_report_tab()

    def _selected_report(self):
        sel = self.tree_report.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择一份报告。")
            return None
        rid = sel[0]
        return rc if (rc := self.report_mgr.get(rid)) else None

    def _refresh_report_tab(self):
        try:
            mgr = self.report_mgr
            mgr.rescan_outputs()
            rows = mgr.list()
            self.tree_report.delete(*self.tree_report.get_children())
            path_set = set()
            for r in rows:
                p = r.get("path", "")
                if p in path_set:
                    continue
                path_set.add(p)
                self.tree_report.insert("", "end", iid=r.get("id"), values=(
                    r.get("title", ""), r.get("school", ""),
                    r.get("created", ""), r.get("confirmed", 0), p))
            self.report_status_label.config(text=f"已缓存报告：{len(path_set)} 份  (缓存目录: "
                                                 f"e:\\trae自动化\\edu-src-toolkit\\outputs\\reports)")
        except Exception as e:
            self.report_status_label.config(text=f"刷新失败：{e}")

    def _report_open(self):
        r = self._selected_report()
        if not r:
            return
        p = REPORT_MGR.open(r.get("id"))
        if not p:
            messagebox.showerror("错误", "报告文件不存在或无法打开。")
            return
        self._append_log(f"已打开报告：{p}", "ok")

    def _report_view(self):
        r = self._selected_report()
        if not r:
            return
        title, text = REPORT_MGR.read(r.get("id"))
        if title is None:
            messagebox.showerror("错误", "无法读取报告内容。")
            return
        win = tk.Toplevel(self.root)
        win.title(f"查看报告：{title}")
        win.geometry("900x620")
        banner = tk.Label(win, text=f"报告：{title}\n路径：{r.get('path','')}",
                          font=("Microsoft YaHei UI", 10, "bold"),
                          fg="#dcdcdc", bg="#2b579a", justify="left", anchor="w", pady=8, padx=12)
        banner.pack(fill="x")
        txt = tk.Text(win, wrap="word", font=("Consolas", 10))
        sb = ttk.Scrollbar(win, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        sb.pack(side="right", fill="y")
        txt.insert("1.0", text if text else "(空)")
        txt.configure(state="disabled")

    def _report_rename(self):
        r = self._selected_report()
        if not r:
            return
        new = tk.simpledialog.askstring(
            "重命名报告", "新的报告标题：", initialvalue=r.get("title", ""),
            parent=self.root)
        if not new or not new.strip():
            return
        REPORT_MGR.update_title(r.get("id"), new.strip())
        self._refresh_report_tab()
        self._append_log(f"报告已重命名：{new.strip()}", "ok")

    def _report_delete(self):
        r = self._selected_report()
        if not r:
            return
        if not messagebox.askyesno("确认删除",
                                   f"确定删除缓存报告「{r.get('title','')}」？\n"
                                   f"仅删除缓存副本 {r.get('cached','')}\n"
                                   f"原始报告{Path(r.get('path','')).resolve()}"
                                   f"{'仍将保留。' if r.get('cached','') != r.get('path','') else '即缓存本身，将一并删除。'}"):
            return
        REPORT_MGR.delete(r.get("id"))
        self._refresh_report_tab()
        self._append_log("报告缓存已删除。", "ok")

    # ---- Webshell 管理标签页 ----
    def _build_webshell_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Webshell管理 ")

        # 顶部工具栏
        toolbar = ttk.Frame(tab, padding=4)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="➕ 新增连接", command=self._ws_add).pack(side="left", padx=2)
        ttk.Button(toolbar, text="✏️ 编辑", command=self._ws_edit).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🗑 删除", command=self._ws_delete).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(toolbar, text="🚀 启动管理器", command=self._ws_launch).pack(side="left", padx=2)
        ttk.Button(toolbar, text="🔄 刷新", command=self._ws_refresh).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=6)
        ttk.Button(toolbar, text="🛠 生成Webshell", command=self._ws_generate).pack(side="left", padx=2)
        ttk.Button(toolbar, text="📂 打开Webshell目录", command=self._ws_open_dir).pack(side="left", padx=2)

        # 连接列表
        list_frame = ttk.Frame(tab)
        list_frame.pack(fill="both", expand=True, padx=4, pady=4)

        columns = ("name", "url", "type", "manager", "password", "created", "last_used")
        self.tree_ws = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)
        self.tree_ws.heading("name", text="名称")
        self.tree_ws.heading("url", text="URL")
        self.tree_ws.heading("type", text="类型")
        self.tree_ws.heading("manager", text="管理器")
        self.tree_ws.heading("password", text="密码")
        self.tree_ws.heading("created", text="创建时间")
        self.tree_ws.heading("last_used", text="最近使用")
        for col in columns:
            self.tree_ws.column(col, width=120 if col != "url" else 250)

        sb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree_ws.yview)
        self.tree_ws.configure(yscrollcommand=sb.set)
        self.tree_ws.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree_ws.bind("<Double-1>", lambda e: self._ws_launch())

        # 状态栏
        self.ws_status = ttk.Label(tab, text="就绪", foreground="#888")
        self.ws_status.pack(anchor="w", padx=6, pady=2)

        # 初始化 webshell 管理器
        from src.webshell.manager import default_manager
        self.ws_mgr = default_manager()
        self._ws_refresh()

    def _ws_refresh(self):
        """刷新 Webshell 连接列表"""
        self.tree_ws.delete(*self.tree_ws.get_children())
        for c in self.ws_mgr.list():
            self.tree_ws.insert("", "end", iid=c.name, values=(
                c.name, c.url, c.shell_type, c.manager,
                c.password, c.created, c.last_used
            ))
        self.ws_status.config(text=f"共 {len(self.ws_mgr.list())} 个连接")

    def _ws_add(self):
        """新增 Webshell 连接"""
        dlg = tk.Toplevel(self.root)
        dlg.title("新增 Webshell 连接")
        dlg.geometry("500x400")
        dlg.transient(self.root)
        dlg.grab_set()

        fields = {}
        row = 0
        for label, key, default in [
            ("名称:", "name", ""),
            ("URL:", "url", "http://"),
            ("密码:", "password", ""),
            ("密钥:", "secret_key", ""),
            ("类型:", "shell_type", "jsp"),
            ("管理器:", "manager", "godzilla"),
            ("备注:", "notes", ""),
        ]:
            ttk.Label(dlg, text=label).grid(row=row, column=0, sticky="e", padx=8, pady=4)
            if key in ("shell_type", "manager"):
                var = tk.StringVar(value=default)
                cb = ttk.Combobox(dlg, textvariable=var, state="readonly", width=20)
                if key == "shell_type":
                    cb["values"] = ("jsp", "jspx", "php", "asp", "aspx")
                else:
                    cb["values"] = ("godzilla", "behinder", "behinder4", "antsword", "tianxi", "ether_ghost")
                cb.grid(row=row, column=1, sticky="w", padx=8, pady=4)
                fields[key] = var
            else:
                entry = ttk.Entry(dlg, width=40)
                entry.insert(0, default)
                entry.grid(row=row, column=1, sticky="w", padx=8, pady=4)
                fields[key] = entry
            row += 1

        def save():
            from src.webshell.manager import WebshellConnection
            vals = {}
            for k, v in fields.items():
                if isinstance(v, tk.StringVar):
                    vals[k] = v.get()
                else:
                    vals[k] = v.get()
            if not vals.get("name") or not vals.get("url"):
                messagebox.showerror("错误", "名称和URL不能为空")
                return
            conn = WebshellConnection(**vals)
            self.ws_mgr.add(conn)
            self._ws_refresh()
            self._append_log(f"已添加 Webshell 连接: {vals['name']}", "ok")
            dlg.destroy()

        ttk.Button(dlg, text="保存", command=save).grid(row=row, column=0, columnspan=2, pady=10)

    def _ws_edit(self):
        """编辑 Webshell 连接"""
        sel = self.tree_ws.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一个连接")
            return
        name = sel[0]
        conn = self.ws_mgr.get(name)
        if not conn:
            return

        dlg = tk.Toplevel(self.root)
        dlg.title(f"编辑连接: {name}")
        dlg.geometry("500x400")
        dlg.transient(self.root)
        dlg.grab_set()

        fields = {}
        row = 0
        for label, key in [
            ("名称:", "name"),
            ("URL:", "url"),
            ("密码:", "password"),
            ("密钥:", "secret_key"),
            ("类型:", "shell_type"),
            ("管理器:", "manager"),
            ("备注:", "notes"),
        ]:
            ttk.Label(dlg, text=label).grid(row=row, column=0, sticky="e", padx=8, pady=4)
            val = getattr(conn, key, "")
            if key in ("shell_type", "manager"):
                var = tk.StringVar(value=val)
                cb = ttk.Combobox(dlg, textvariable=var, state="readonly", width=20)
                if key == "shell_type":
                    cb["values"] = ("jsp", "jspx", "php", "asp", "aspx")
                else:
                    cb["values"] = ("godzilla", "behinder", "behinder4", "antsword", "tianxi", "ether_ghost")
                cb.grid(row=row, column=1, sticky="w", padx=8, pady=4)
                fields[key] = var
            else:
                entry = ttk.Entry(dlg, width=40)
                entry.insert(0, val)
                entry.grid(row=row, column=1, sticky="w", padx=8, pady=4)
                fields[key] = entry
            row += 1

        def save():
            vals = {}
            for k, v in fields.items():
                if isinstance(v, tk.StringVar):
                    vals[k] = v.get()
                else:
                    vals[k] = v.get()
            old_name = name
            new_name = vals.pop("name", old_name)
            self.ws_mgr.remove(old_name)
            from src.webshell.manager import WebshellConnection
            conn_new = WebshellConnection(name=new_name, **vals)
            self.ws_mgr.add(conn_new)
            self._ws_refresh()
            self._append_log(f"已更新 Webshell 连接: {new_name}", "ok")
            dlg.destroy()

        ttk.Button(dlg, text="保存", command=save).grid(row=row, column=0, columnspan=2, pady=10)

    def _ws_delete(self):
        """删除 Webshell 连接"""
        sel = self.tree_ws.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一个连接")
            return
        name = sel[0]
        if messagebox.askyesno("确认删除", f"确定删除连接「{name}」？"):
            self.ws_mgr.remove(name)
            self._ws_refresh()
            self._append_log(f"已删除 Webshell 连接: {name}", "ok")

    def _ws_launch(self):
        """启动 Webshell 管理器"""
        sel = self.tree_ws.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一个连接")
            return
        name = sel[0]
        conn = self.ws_mgr.get(name)
        if not conn:
            return
        ok, msg = self.ws_mgr.launch_manager(conn)
        if ok:
            self._append_log(msg, "ok")
            self._ws_refresh()
        else:
            messagebox.showerror("启动失败", msg)

    def _ws_generate(self):
        """生成 Webshell"""
        dlg = tk.Toplevel(self.root)
        dlg.title("生成 Webshell")
        dlg.geometry("400x200")
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(dlg, text="选择 Webshell 类型:").pack(pady=10)
        shell_type = tk.StringVar(value="jsp")
        cb = ttk.Combobox(dlg, textvariable=shell_type, state="readonly", width=20)
        cb["values"] = ("jsp", "jspx", "php", "asp", "aspx")
        cb.pack(pady=5)

        def generate():
            ok, msg, path = self.ws_mgr.generate_shell(shell_type.get())
            if ok:
                messagebox.showinfo("生成成功", f"{msg}\n\n路径: {path}")
                self._append_log(f"Webshell 生成成功: {path}", "ok")
            else:
                messagebox.showerror("生成失败", msg)
            dlg.destroy()

        ttk.Button(dlg, text="生成", command=generate).pack(pady=20)

    def _ws_open_dir(self):
        """打开 Webshell 输出目录"""
        from src.config import OUTPUTS_DIR
        ws_dir = OUTPUTS_DIR / "webshells"
        ws_dir.mkdir(parents=True, exist_ok=True)
        os.startfile(str(ws_dir))

    # ---------------- 交互逻辑 ----------------
    def _append_log(self, msg, kind="info"):
        tags = {"info": "#dcdcdc", "error": "#ff7b72", "ok": "#7ee787",
                "warn": "#e3b341"}
        color = tags.get(kind, "#dcdcdc")
        self.log_text.configure(state="normal")
        line = f"[{type('x')}] " if False else ""
        self.log_text.insert("end", f"{msg}\n", (kind,))
        self.log_text.tag_configure(kind, foreground=color)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _do_search(self, event=None):
        kw = self.school_search.get().strip()
        if not kw:
            self._show_all_schools()
            return
        cands = search(kw)
        self._populate_schools(cands)
        if cands:
            messagebox.showinfo("搜索结果", f"找到 {len(cands)} 所学校，请在下拉框选择。\n(可继续换关键词搜索)")

    def _show_all_schools(self):
        self._populate_schools(UNIVERSITIES)

    def _populate_schools(self, cands):
        self.school_box["values"] = [f"{u['name']} ({u['code']})" for u in cands]
        self.school_box.set("")
        self.school_box._cands = cands

    def _select_school(self):
        idx = self.school_box.current()
        cands = getattr(self.school_box, "_cands", [])
        if idx < 0 or not cands:
            messagebox.showwarning("提示", "请先在搜索框搜索并选择一个学校。")
            return
        self.current_school = cands[idx]
        self.sel_label.config(text=f"已选：{self.current_school['name']}  ",
                              foreground="#2b579a")
        self._append_log(f"选择目标：{self.current_school['name']} "
                         f"({self.current_school['domains'][0]})", "ok")

    # ---------------- 流程启动 ----------------
    def _require_school(self):
        if not self.current_school:
            messagebox.showwarning("提示", "请先搜索并选择目标学校。")
            return False
        return True

    def _spawn(self, stage):
        """开后台线程执行 pipeline 方法；同一stage不会重复启动"""
        if self._stages.get(stage):
            messagebox.showinfo("提示", f"{stage} 正在运行中，请稍候。")
            return
        if not self.pipeline:
            self.pipeline = Pipeline(self.current_school, self._post_event)
        t = threading.Thread(target=self._run_stage, args=(stage, self.pipeline),
                             daemon=True)
        self._stages[stage] = True
        self.progress.start(12)
        t.start()

    def _run_stage(self, stage, pipe):
        try:
            {
                "资产收集": pipe.run_recon,
                "漏洞挖掘": pipe.run_vuln,
                "复测": pipe.run_reverify,
                "报告": pipe.run_report,
                "全流程": pipe.run_full,
            }[stage]()
        except Exception as e:
            self._post_event({"type": "log", "msg": f"后台异常：{e}", "kind": "error"})
        finally:
            self._stages[stage] = False
            stage = stage  # noop

    def _start_recon(self):
        if self._require_school():
            self._spawn("资产收集")

    def _start_vuln(self):
        if self._require_school():
            self._spawn("漏洞挖掘")

    def _start_reverify(self):
        if self._require_school():
            self._spawn("复测")

    def _start_report(self):
        if self._require_school():
            self._spawn("报告")

    def _start_full(self):
        if not self._require_school():
            return
        if self._stages.get("全流程"):
            return
        if not self.pipeline:
            self.pipeline = Pipeline(self.current_school, self._post_event)
        self._stages["全流程"] = True
        self.progress.start(12)
        threading.Thread(target=lambda: self._full_worker(self.pipeline), daemon=True).start()

    def _full_worker(self, pipe):
        try:
            pipe.run_recon()
            if pipe._check_stop():
                return
            pipe.run_vuln()
            if pipe._check_stop():
                return
            pipe.run_reverify()
            pipe.run_report()
            self._post_event({"type": "state", "stage": "全流程", "running": False})
        except Exception as e:
            self._post_event({"type": "log", "msg": f"全流程异常：{e}", "kind": "error"})
        finally:
            self._stages["全流程"] = False

    def _stop_all(self):
        if self.pipeline:
            self.pipeline.stop()
        self._append_log(">>> 已请求停止（等待当前步骤结束）", "warn")

    # ---------------- 事件处理 ----------------
    def _post_event(self, ev):
        self.events.put(ev)

    def _drain_events(self):
        try:
            while True:
                ev = self.events.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        # 进度条状态
        any_running = any(self._stages.values())
        if any_running:
            self.stage_label.config(text="运行中： " + "、".join(
                [k for k, v in self._stages.items() if v]))
        else:
            self.stage_label.config(text="空闲")
            self.progress.stop()
        self.root.after(120, self._drain_events)

    def _handle_event(self, ev):
        t = ev.get("type")
        if t == "log":
            self._append_log(ev["msg"], ev.get("kind", "info"))
        elif t == "state":
            pass
        elif t == "subdomains":
            self._fill_subs(ev["data"])
        elif t == "alive":
            self._fill_alive(ev["data"])
        elif t == "findings":
            self._fill_findings(ev["data"])
        elif t == "nday":
            self._fill_nday(ev["data"])
        elif t == "nday_verified":
            self._append_log(f"Nday特征验证命中 {len(ev['data'])} 处（详见outputs/nday_verified.json）", "ok")
        elif t == "reverify":
            self._merge_reverify(ev["data"])
        elif t == "report":
            self._ask_open(ev["path"], "报告")
            self._refresh_report_tab()
        elif t == "report_registered":
            self._refresh_report_tab()

    # ---------------- 表格填充 ----------------
    def _fill_subs(self, data):
        self.tree_subs.delete(*self.tree_subs.get_children())
        for s in data:
            self.tree_subs.insert("", "end", values=(s,))

    def _fill_alive(self, data):
        self.tree_alive.delete(*self.tree_alive.get_children())
        for fp in data:
            self.tree_alive.insert("", "end", values=(
                fp.get("url", ""), fp.get("status", ""), fp.get("title", ""),
                ",".join(fp.get("hits", [])[:3])))
        self._append_log(f"存活资产表格更新：{len(data)} 条", "ok")

    def _fill_findings(self, data):
        self.tree_find.delete(*self.tree_find.get_children())
        for rec in data:
            self.tree_find.insert("", "end", values=(
                rec.get("url", ""), rec.get("type", ""), rec.get("sev", ""), ""))
        self._append_log(f"漏洞表格更新：{len(data)} 条", "ok")

    def _fill_nday(self, data):
        self.tree_nday.delete(*self.tree_nday.get_children())
        for c in data:
            self.tree_nday.insert("", "end", values=(
                c.get("fingerprint", ""), c.get("keyword", ""),
                c.get("cve") or c.get("cnvd", ""), c.get("desc", "")[:80]))
        self.nday_label.config(text=f"Nday候选：{len(data)}（需授权确认后再验证/上报）")
        self._append_log(f"Nday线索更新：{len(data)} 条", "ok")

    def _merge_reverify(self, out):
        rmap = {}
        for rec in out.get("findings", []):
            rmap[rec.get("url", "") + rec.get("type", "")] = rec.get("reverify", {})
        # 更新findings表
        for item in self.tree_find.get_children():
            vals = self.tree_find.item(item, "values")
            key = vals[0] + vals[1]
            rv = rmap.get(key)
            if rv:
                self.tree_find.set(item, "verify",
                                   f"{rv.get('status')} {rv.get('reason','')[:30]}")
        self._append_log("复测状态已合并进表格", "ok")

    def _ask_open(self, path, what):
        if messagebox.askyesno("完成", f"{what}已生成：\n{path}\n\n是否打开？"):
            try:
                os.startfile(path)
            except Exception:
                self._append_log(f"无法自动打开：{path}", "warn")

    def _on_close(self):
        if self.pipeline:
            self.pipeline.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    # 尝试设置窗口图标（源码运行时从icon_src读取，打包后含app_icon.ico）
    for _cand in (Path(__file__).resolve().parent / "app_icon.ico",
                  Path(r"e:\trae自动化\edu-src-toolkit\app_icon.ico")):
        try:
            if _cand.exists():
                root.iconbitmap(str(_cand))
                break
        except Exception:
            pass
    app = EduSrcGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()