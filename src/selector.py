# -*- coding: utf-8 -*-
"""选校交互模块 - 支持搜索/列表/选择"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from data.universities import UNIVERSITIES, get, search


def show_menu(candidates):
    """打印候选列表"""
    print("\n" + "=" * 56)
    for idx, u in enumerate(candidates, 1):
        print(f"  {idx:>2}. {u['name']:<16}  {u['code']:<14}  {u['domains'][0]}")
    print("=" * 56)


def pick(candidates):
    """让用户从候选里选择 1..n，回车=全部，q=退出"""
    while True:
        raw = input("\n选择学校编号（可逗号/空格分隔多个，回车=全部，q=退出）：").strip()
        if not raw:
            return candidates
        if raw.lower() in ("q", "quit", "退出", "exit"):
            sys.exit(0)
        try:
            idxs = [int(x) for x in raw.replace("，", ",").replace(" ", ",").split(",") if x.strip()]
            picked = [candidates[i - 1] for i in idxs if 1 <= i <= len(candidates)]
            if picked:
                return picked
            print("  ! 无效编号，请重新输入")
        except ValueError:
            print("  ! 无法解析输入，请用数字编号")


def select_universities():
    """
    选校主流程：返回用户选定的大学列表。
    - 支持直接输入数字编号
    - 支持搜索（名称/拼音后缀）
    """
    print("\n" + "─" * 56)
    print("  教育SRC 挖洞工具 - 选择目标学校")
    print("  共收录 %d 所高校" % len(UNIVERSITIES))
    print("─" * 56)

    while True:
        kw = input("\n输入关键词搜索学校（名称/拼音代号，如 '北京' 'zju' '清华'），回车查看全部：").strip()
        if kw.lower() in ("q", "quit", "退出"):
            sys.exit(0)

        if not kw:
            candidates = UNIVERSITIES
        else:
            candidates = search(kw)
            if not candidates:
                print(f"  ! 未找到匹配 '{kw}' 的学校")
                continue

        show_menu(candidates)
        return pick(candidates)


if __name__ == "__main__":
    schools = select_universities()
    print("\n已选择：")
    for s in schools:
        print(f"  - {s['name']} ({s['code']})  {s['domains'][0]}")