# -*- coding: utf-8 -*-
"""Webshell 管理模块

集成主流 Webshell 管理工具（哥斯拉/冰蝎/蚁剑/天禧），支持：
- Webshell 连接管理（增删改查）
- 一键启动对应管理器
- Webshell 生成（调用 Webshell_Generate 工具）
- 连接信息本地缓存
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

# 工具路径（可通过环境变量 TOOLS_ROOT 覆盖）
TOOLS_ROOT = Path(os.environ.get("TOOLS_ROOT", r"F:\One-fox\tools"))
WEBSHELL_DIR = TOOLS_ROOT / "gui_webshell"
WEBSHELL_GEN = TOOLS_ROOT / "gui_other" / "webshellsc" / "Webshell_Generate-1.2.4.jar"

# 各管理器路径
MANAGERS = {
    "godzilla": WEBSHELL_DIR / "Godzilla" / "godzilla.jar",
    "behinder": WEBSHELL_DIR / "Behinder" / "Behinder.jar",
    "behinder4": WEBSHELL_DIR / "Behinder4" / "Behinder.jar",
    "antsword": WEBSHELL_DIR / "alien" / "WebShell.exe",
    "tianxi": WEBSHELL_DIR / "TianXie" / "天蝎权限管理工具.jar",
    "ether_ghost": WEBSHELL_DIR / "yh" / "ether_ghost_v0.2.0.exe",
}

# C2 框架路径
C2_FRAMEWORKS = {
    "cobaltstrike": WEBSHELL_DIR.parent / "gui_other" / "Cobalt_Strike_4.7" / "cobaltstrike.jar",
    "cobaltstrike_client": WEBSHELL_DIR.parent / "gui_other" / "Cobalt_Strike_4.7" / "cobaltstrike-client.jar",
    "dogcs": WEBSHELL_DIR.parent / "gui_other" / "dogcs_v2.1" / "TeamServer64.exe",
    "xiebro_c2": WEBSHELL_DIR.parent / "gui_other" / "dogcs_v2.1" / "XieBroC2.exe",
    "counter_strike": WEBSHELL_DIR.parent / "gui_other" / "Counter-Strike" / "TeamServer.jar",
    "cs_client": WEBSHELL_DIR.parent / "gui_other" / "Counter-Strike" / "cs.jar",
}

# Webshell 类型与对应管理器映射
SHELL_TYPE_MAP = {
    "jsp": ["godzilla", "behinder", "behinder4"],
    "jspx": ["godzilla", "behinder4"],
    "php": ["godzilla", "behinder", "antsword"],
    "asp": ["antsword", "tianxi"],
    "aspx": ["antsword", "tianxi", "godzilla"],
}


class WebshellConnection:
    """Webshell 连接信息"""
    def __init__(self, name="", url="", password="", secret_key="", 
                 shell_type="jsp", manager="godzilla", notes=""):
        self.name = name
        self.url = url
        self.password = password
        self.secret_key = secret_key
        self.shell_type = shell_type  # jsp/php/asp/aspx
        self.manager = manager  # godzilla/behinder/antsword/tianxi
        self.notes = notes
        self.created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_used = ""

    def to_dict(self):
        return {
            "name": self.name,
            "url": self.url,
            "password": self.password,
            "secret_key": self.secret_key,
            "shell_type": self.shell_type,
            "manager": self.manager,
            "notes": self.notes,
            "created": self.created,
            "last_used": self.last_used,
        }

    @classmethod
    def from_dict(cls, d):
        c = cls()
        for k, v in d.items():
            if hasattr(c, k):
                setattr(c, k, v)
        return c


class WebshellManager:
    """Webshell 管理器"""

    def __init__(self, cache_file=None):
        from src.config import OUTPUTS_DIR
        self.cache_file = cache_file or (OUTPUTS_DIR / "webshell_connections.json")
        self.connections = self._load()

    def _load(self):
        """加载缓存的连接"""
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                return [WebshellConnection.from_dict(d) for d in data]
            except Exception:
                return []
        return []

    def _save(self):
        """保存连接到缓存"""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        data = [c.to_dict() for c in self.connections]
        self.cache_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8")

    def add(self, conn: WebshellConnection):
        """添加连接"""
        self.connections.append(conn)
        self._save()
        return conn

    def remove(self, name):
        """删除连接"""
        self.connections = [c for c in self.connections if c.name != name]
        self._save()

    def update(self, name, **kwargs):
        """更新连接"""
        for c in self.connections:
            if c.name == name:
                for k, v in kwargs.items():
                    if hasattr(c, k):
                        setattr(c, k, v)
                self._save()
                return c
        return None

    def get(self, name):
        """获取连接"""
        for c in self.connections:
            if c.name == name:
                return c
        return None

    def list(self):
        """列出所有连接"""
        return self.connections

    def mark_used(self, name):
        """标记为最近使用"""
        for c in self.connections:
            if c.name == name:
                c.last_used = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._save()
                return

    def launch_manager(self, conn: WebshellConnection = None, manager_name: str = None):
        """启动 Webshell 管理器

        conn: 指定连接（会传递 URL/密码等参数）
        manager_name: 指定管理器名称（godzilla/behinder/antsword/tianxi）
        """
        if conn and not manager_name:
            manager_name = conn.manager
        if not manager_name:
            manager_name = "godzilla"

        jar_path = MANAGERS.get(manager_name)
        if not jar_path or not jar_path.exists():
            return False, f"未找到管理器: {manager_name} ({jar_path})"

        try:
            if jar_path.suffix == ".jar":
                # Java 管理器
                cmd = ["javaw", "-jar", str(jar_path)]
            else:
                # EXE 管理器
                cmd = [str(jar_path)]

            # 启动进程
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            
            if conn:
                self.mark_used(conn.name)
                return True, f"已启动 {manager_name}，连接: {conn.url}"
            return True, f"已启动 {manager_name}"
        except Exception as e:
            return False, f"启动失败: {e}"

    def generate_shell(self, shell_type="jsp", encrypt_type="default", output_dir=None):
        """生成 Webshell

        shell_type: jsp/php/asp/aspx
        encrypt_type: 加密类型（取决于生成工具支持）
        output_dir: 输出目录
        """
        if not WEBSHELL_GEN.exists():
            return False, f"未找到 Webshell 生成工具: {WEBSHELL_GEN}"

        if not output_dir:
            from src.config import OUTPUTS_DIR
            output_dir = OUTPUTS_DIR / "webshells"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # 调用生成工具
            cmd = ["java", "-jar", str(WEBSHELL_GEN), 
                   "-type", shell_type,
                   "-out", str(output_dir)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # 查找生成的文件
                shells = list(output_dir.glob(f"*.{shell_type}"))
                if shells:
                    latest = max(shells, key=lambda p: p.stat().st_mtime)
                    return True, f"生成成功: {latest}", str(latest)
                return True, "生成成功，但未找到输出文件"
            else:
                return False, f"生成失败: {result.stderr}"
        except Exception as e:
            return False, f"生成异常: {e}"


def default_manager():
    """获取默认管理器实例"""
    _m = getattr(default_manager, "_m", None)
    if _m is None:
        _m = WebshellManager()
        default_manager._m = _m
    return _m


def launch_c2(c2_name: str, teamserver_host: str = "0.0.0.0", teamserver_port: int = 50050,
              password: str = "123456", extra_args: str = ""):
    """启动 C2 框架

    c2_name: cobaltstrike / dogcs / xiebro_c2 / counter_strike
    teamserver_host: TeamServer 监听地址
    teamserver_port: TeamServer 监听端口
    password: TeamServer 密码
    extra_args: 额外参数
    """
    jar_path = C2_FRAMEWORKS.get(c2_name)
    if not jar_path or not jar_path.exists():
        return False, f"未找到 C2 框架: {c2_name} ({jar_path})"

    try:
        if jar_path.suffix == ".jar":
            # Java C2 (CobaltStrike, Counter-Strike)
            cmd = ["java", "-XX:ParallelGCThreads=4", "-XX:+AggressiveHeap",
                   "-jar", str(jar_path), teamserver_host, password]
            if extra_args:
                cmd.extend(extra_args.split())
        else:
            # EXE C2 (dogcs, xiebro)
            cmd = [str(jar_path), f"--host={teamserver_host}", f"--port={teamserver_port}"]
            if password:
                cmd.append(f"--password={password}")
            if extra_args:
                cmd.extend(extra_args.split())

        subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        return True, f"已启动 {c2_name}，TeamServer: {teamserver_host}:{teamserver_port}"
    except Exception as e:
        return False, f"启动失败: {e}"


def list_c2():
    """列出可用的 C2 框架"""
    result = []
    for name, path in C2_FRAMEWORKS.items():
        result.append({
            "name": name,
            "path": str(path),
            "exists": path.exists(),
        })
    return result


if __name__ == "__main__":
    m = default_manager()
    print("Webshell 连接列表:")
    for c in m.list():
        print(f"  {c.name}: {c.url} ({c.shell_type}, {c.manager})")
