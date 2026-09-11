# -*- coding: utf-8 -*-
"""教育SRC挖洞 - 大学数据库

内置国内高校信息，用于选校与自动信息收集。
知识来源：公开的高校官方域名（edu.cn）信息。

说明：仅收录各高校公开的官方主域名与常见子站域名字段，
不含任何敏感或私有数据。用户可自行增删条目。
"""

# 高校数据：name=校名, code=校名拼音缩写, domains=官方域名/常见资产后缀
# 域名省略写法：如 "tsinghua" 代表 tsinghua.edu.cn
UNIVERSITIES = [
    # ---- 北京 ----
    {"name": "清华大学", "code": "tsinghua", "domains": ["tsinghua.edu.cn"]},
    {"name": "北京大学", "code": "pku", "domains": ["pku.edu.cn"]},
    {"name": "中国人民大学", "code": "ruc", "domains": ["ruc.edu.cn"]},
    {"name": "北京师范大学", "code": "bnu", "domains": ["bnu.edu.cn"]},
    {"name": "北京航空航天大学", "code": "buaa", "domains": ["buaa.edu.cn"]},
    {"name": "北京理工大学", "code": "bit", "domains": ["bit.edu.cn"]},
    {"name": "中国农业大学", "code": "cau", "domains": ["cau.edu.cn"]},
    {"name": "中央民族大学", "code": "muc", "domains": ["muc.edu.cn"]},
    {"name": "北京邮电大学", "code": "bupt", "domains": ["bupt.edu.cn"]},
    {"name": "北京交通大学", "code": "bjtu", "domains": ["bjtu.edu.cn"]},
    {"name": "北京科技大学", "code": "ustb", "domains": ["ustb.edu.cn"]},
    {"name": "北京化工大学", "code": "buct", "domains": ["buct.edu.cn"]},
    {"name": "北京外国语大学", "code": "bfsu", "domains": ["bfsu.edu.cn"]},
    {"name": "北京语言大学", "code": "blcu", "domains": ["blcu.edu.cn"]},
    {"name": "对外经济贸易大学", "code": "uibe", "domains": ["uibe.edu.cn"]},
    {"name": "中央财经大学", "code": "cufe", "domains": ["cufe.edu.cn"]},
    {"name": "中国政法大学", "code": "cupl", "domains": ["cupl.edu.cn"]},
    {"name": "中国传媒大学", "code": "cuc", "domains": ["cuc.edu.cn"]},
    {"name": "首都师范大学", "code": "cnu", "domains": ["cnu.edu.cn"]},
    {"name": "北京工业大学", "code": "bjut", "domains": ["bjut.edu.cn"]},
    # ---- 上海 ----
    {"name": "复旦大学", "code": "fudan", "domains": ["fudan.edu.cn"]},
    {"name": "上海交通大学", "code": "sjtu", "domains": ["sjtu.edu.cn"]},
    {"name": "同济大学", "code": "tongji", "domains": ["tongji.edu.cn"]},
    {"name": "华东师范大学", "code": "ecnu", "domains": ["ecnu.edu.cn"]},
    {"name": "华东理工大学", "code": "ecust", "domains": ["ecust.edu.cn"]},
    {"name": "上海大学", "code": "shu", "domains": ["shu.edu.cn"]},
    {"name": "东华大学", "code": "dhu", "domains": ["dhu.edu.cn"]},
    {"name": "上海外国语大学", "code": "shisu", "domains": ["shisu.edu.cn"]},
    {"name": "上海财经大学", "code": "shufe", "domains": ["shufe.edu.cn"]},
    # ---- 天津 ----
    {"name": "天津大学", "code": "tju", "domains": ["tju.edu.cn"]},
    {"name": "南开大学", "code": "nankai", "domains": ["nankai.edu.cn"]},
    # ---- 重庆 ----
    {"name": "重庆大学", "code": "cqu", "domains": ["cqu.edu.cn"]},
    {"name": "西南大学", "code": "swu", "domains": ["swu.edu.cn"]},
    # ---- 黑龙江 ----
    {"name": "哈尔滨工业大学", "code": "hit", "domains": ["hit.edu.cn"]},
    {"name": "哈尔滨工程大学", "code": "hrbeu", "domains": ["hrbeu.edu.cn"]},
    {"name": "东北林业大学", "code": "nefu", "domains": ["nefu.edu.cn"]},
    {"name": "东北农业大学", "code": "neau", "domains": ["neau.edu.cn"]},
    # ---- 吉林 ----
    {"name": "吉林大学", "code": "jlu", "domains": ["jlu.edu.cn"]},
    {"name": "东北师范大学", "code": "nenu", "domains": ["nenu.edu.cn"]},
    {"name": "延边大学", "code": "ybu", "domains": ["ybu.edu.cn"]},
    # ---- 辽宁 ----
    {"name": "大连理工大学", "code": "dlut", "domains": ["dlut.edu.cn"]},
    {"name": "东北大学", "code": "neu", "domains": ["neu.edu.cn"]},
    {"name": "辽宁大学", "code": "lnu", "domains": ["lnu.edu.cn"]},
    {"name": "大连海事大学", "code": "dlmu", "domains": ["dlmu.edu.cn"]},
    # ---- 山东 ----
    {"name": "山东大学", "code": "sdu", "domains": ["sdu.edu.cn"]},
    {"name": "中国海洋大学", "code": "ouc", "domains": ["ouc.edu.cn"]},
    {"name": "中国石油大学（华东）", "code": "upc", "domains": ["upc.edu.cn"]},
    # ---- 江苏 ----
    {"name": "南京大学", "code": "nju", "domains": ["nju.edu.cn"]},
    {"name": "东南大学", "code": "seu", "domains": ["seu.edu.cn"]},
    {"name": "南京航空航天大学", "code": "nuaa", "domains": ["nuaa.edu.cn"]},
    {"name": "南京理工大学", "code": "njust", "domains": ["njust.edu.cn"]},
    {"name": "河海大学", "code": "hhu", "domains": ["hhu.edu.cn"]},
    {"name": "江南大学", "code": "jiangnan", "domains": ["jiangnan.edu.cn"]},
    {"name": "中国矿业大学", "code": "cumt", "domains": ["cumt.edu.cn"]},
    {"name": "南京农业大学", "code": "njau", "domains": ["njau.edu.cn"]},
    {"name": "南京师范大学", "code": "njnu", "domains": ["njnu.edu.cn"]},
    {"name": "苏州大学", "code": "suda", "domains": ["suda.edu.cn"]},
    {"name": "南京邮电大学", "code": "njupt", "domains": ["njupt.edu.cn"]},
    # ---- 浙江 ----
    {"name": "浙江大学", "code": "zju", "domains": ["zju.edu.cn"]},
    # ---- 安徽 ----
    {"name": "中国科学技术大学", "code": "ustc", "domains": ["ustc.edu.cn"]},
    {"name": "合肥工业大学", "code": "hfut", "domains": ["hfut.edu.cn"]},
    {"name": "安徽大学", "code": "ahu", "domains": ["ahu.edu.cn"]},
    # ---- 福建 ----
    {"name": "厦门大学", "code": "xmu", "domains": ["xmu.edu.cn"]},
    {"name": "福州大学", "code": "fzu", "domains": ["fzu.edu.cn"]},
    # ---- 湖北 ----
    {"name": "武汉大学", "code": "whu", "domains": ["whu.edu.cn"]},
    {"name": "华中科技大学", "code": "hust", "domains": ["hust.edu.cn"]},
    {"name": "中国地质大学（武汉）", "code": "cug", "domains": ["cug.edu.cn"]},
    {"name": "武汉理工大学", "code": "whut", "domains": ["whut.edu.cn"]},
    {"name": "华中师范大学", "code": "ccnu", "domains": ["ccnu.edu.cn"]},
    {"name": "华中农业大学", "code": "hzau", "domains": ["hzau.edu.cn"]},
    {"name": "中南财经政法大学", "code": "zuel", "domains": ["zuel.edu.cn"]},
    # ---- 湖南 ----
    {"name": "中南大学", "code": "csu", "domains": ["csu.edu.cn"]},
    {"name": "湖南大学", "code": "hnu", "domains": ["hnu.edu.cn"]},
    {"name": "湖南师范大学", "code": "hunnu", "domains": ["hunnu.edu.cn"]},
    {"name": "国防科技大学", "code": "nudt", "domains": ["nudt.edu.cn"]},
    # ---- 广东 ----
    {"name": "中山大学", "code": "sysu", "domains": ["sysu.edu.cn"]},
    {"name": "华南理工大学", "code": "scut", "domains": ["scut.edu.cn"]},
    {"name": "暨南大学", "code": "jnu", "domains": ["jnu.edu.cn"]},
    {"name": "华南师范大学", "code": "scnu", "domains": ["scnu.edu.cn"]},
    {"name": "深圳大学", "code": "szu", "domains": ["szu.edu.cn"]},
    {"name": "南方科技大学", "code": "sustech", "domains": ["sustech.edu.cn"]},
    {"name": "广东工业大学", "code": "gdut", "domains": ["gdut.edu.cn"]},
    {"name": "华南农业大学", "code": "scau", "domains": ["scau.edu.cn"]},
    # ---- 广西 ----
    {"name": "广西大学", "code": "gxu", "domains": ["gxu.edu.cn"]},
    # ---- 四川 ----
    {"name": "四川大学", "code": "scu", "domains": ["scu.edu.cn"]},
    {"name": "电子科技大学", "code": "uestc", "domains": ["uestc.edu.cn"]},
    {"name": "西南交通大学", "code": "swjtu", "domains": ["swjtu.edu.cn"]},
    {"name": "西南财经大学", "code": "swufe", "domains": ["swufe.edu.cn"]},
    {"name": "四川农业大学", "code": "sicau", "domains": ["sicau.edu.cn"]},
    # ---- 云南 ----
    {"name": "云南大学", "code": "ynu", "domains": ["ynu.edu.cn"]},
    {"name": "昆明理工大学", "code": "kust", "domains": ["kust.edu.cn"]},
    # ---- 贵州 ----
    {"name": "贵州大学", "code": "gzu", "domains": ["gzu.edu.cn"]},
    # ---- 陕西 ----
    {"name": "西安交通大学", "code": "xjtu", "domains": ["xjtu.edu.cn"]},
    {"name": "西北工业大学", "code": "nwpu", "domains": ["nwpu.edu.cn"]},
    {"name": "西安电子科技大学", "code": "xidian", "domains": ["xidian.edu.cn"]},
    {"name": "西北大学", "code": "nwu", "domains": ["nwu.edu.cn"]},
    {"name": "长安大学", "code": "chd", "domains": ["chd.edu.cn"]},
    {"name": "西北农林科技大学", "code": "nwafu", "domains": ["nwafu.edu.cn"]},
    {"name": "陕西师范大学", "code": "snnu", "domains": ["snnu.edu.cn"]},
    # ---- 甘肃 ----
    {"name": "兰州大学", "code": "lzu", "domains": ["lzu.edu.cn"]},
    # ---- 宁夏 ----
    {"name": "宁夏大学", "code": "nxu", "domains": ["nxu.edu.cn"]},
    # ---- 青海 ----
    {"name": "青海大学", "code": "qhu", "domains": ["qhu.edu.cn"]},
    # ---- 新疆 ----
    {"name": "新疆大学", "code": "xju", "domains": ["xju.edu.cn"]},
    {"name": "石河子大学", "code": "shzu", "domains": ["shzu.edu.cn"]},
    # ---- 西藏 ----
    {"name": "西藏大学", "code": "utibet", "domains": ["utibet.edu.cn"]},
    # ---- 内蒙古 ----
    {"name": "内蒙古大学", "code": "imu", "domains": ["imu.edu.cn"]},
    # ---- 海南 ----
    {"name": "海南大学", "code": "hainanu", "domains": ["hainanu.edu.cn"]},
    # ---- 河南 ----
    {"name": "郑州大学", "code": "zzu", "domains": ["zzu.edu.cn"]},
    {"name": "河南大学", "code": "henu", "domains": ["henu.edu.cn"]},
    # ---- 山西 ----
    {"name": "太原理工大学", "code": "tyut", "domains": ["tyut.edu.cn"]},
    {"name": "山西大学", "code": "sxu", "domains": ["sxu.edu.cn"]},
]


def get_universities():
    """返回全部大学列表"""
    return UNIVERSITIES


def search(name_or_code):
    """按名称或拼音代号搜索大学"""
    kw = name_or_code.strip().lower()
    result = []
    for u in UNIVERSITIES:
        if kw in u["name"].lower() or kw in u["code"].lower():
            result.append(u)
    return result


def get(code):
    """按拼音代号精确获取一所大学"""
    for u in UNIVERSITIES:
        if u["code"] == code:
            return u
    return None