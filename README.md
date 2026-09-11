# 教育SRC 挖洞自动化工具 (edu-src-toolkit)

针对**教育行业漏洞平台 / 高校 SRC** 的公益挖洞自动化工具，集成全国高校，
支持选校后自动执行「资产收集 → 漏洞挖掘 → 复测」全流程，产出一键缓存管理的精准渗透报告。

> ⚠️ **合规声明**：本工具仅用于**获得授权**的公益安全研究。
> 教育网（edu.cn）资产受 CERNET 等机构管理，请在**平台授权范围内**、遵循**负责任披露**原则使用。
> 未经授权对任何目标进行测试属于违法行为，后果自负。

## 一、功能

| 阶段 | 能力 | 输出 |
|------|------|------|
| **选校** | 内置 111 所高校，可按名称/拼音检索选择 | — |
| **资产收集** | 子域名枚举(crt.sh被动+DNS探测+subfinder可选) | subdomains.txt |
| **探活指纹** | HTTP探活、标题、Server、CMS/框架识别 | alive_urls.txt |
| **证据漏洞挖掘** | 敏感文件检测必须 **HTTP200 + 响应体含真实证据特征**，502/403/404一律不判漏洞 | findings.json |
| **主动漏洞验证** | 对输入向量真实注入 **SQLi(报错/布尔盲注差分) / Reflected XSS / 路径穿越·任意文件读取 / 开放重定向**，差分证据链判定 | findings.json |
| **Nday线索** | 产品精确关联本地CNVD（消除"apache"宽泛误报），**仅线索非漏洞** | findings.json |
| **Nday特征验证** | 主动无害行为探测 **Shiro rememberMe deleteMe / Spring Actuator未授权 / WebLogic·Struts·Fastjson 反序列化入口 / ThinkPHP**，确系真实特征则转漏洞 | findings.json |
| **外部扫描器联动** | 自动调用本地 **nuclei / afrog / ehole / fscan / xray**（`F:\One-fox\tools`），覆盖反序列化、XSS、CSRF、SSRF、任意跳转、源码泄露等全部手法，缺任一工具自动降级不中断 | findings.json |
| **攻击过程还原** | 全程记录每个注入点的URL/参数/payload/响应/命中与否 → attack_log | attack_log.json |
| **证据链复测** | 灵敏泄露二次取证；主动漏洞重跑对应判定器再次命中才 confirmed | reverify.json |
| **完整渗透报告** | 含PTES七阶段执行记录、攻击路径与方法、攻击执行明细、证据链、误报剔除区 | 渗透测试报告.md |
| **报告管理** | **自动缓存登记**所有生成报告，内置查看/打开/重命名/删除(仅删缓存副本保留原文)/路径展示的**增删改查** | outputs/reports + 报告管理页 |
| **PoC联动** | 索引 `D:\漏洞库\exploitarium` 本地PoC源码库 | 运行时匹配 |

> **核心设计原则（重要）**：本工具**宁可漏报、不可误报**。
> - **被动泄露**：漏洞必须附带 **HTTP 200 响应体真实证据**（源码/配置/备份内容）才算真漏洞；
>   服务器返回 5xx/4xx（如 502 Bad Gateway）一律判定为误报剔除，绝不进入报告。
> - **主动注入**：SQLi/XSS/路径穿越/开放重定向必须提供**基线-注入差分证据链**（报错签名、
>   AND 1=1/1=2 布尔差分、payload 原样反射、/etc/passwd 真实内容、Location 携带签名域）才判 confirmed；
>   只做**只读·最小影响**验证，不写库、不删改、不执行RCE。
> - **Nday特征**：Shiro deleteMe / Actuator 暴露 / 反序列化入口均为**无害行为探测**得出的真实特征。
> - robots.txt 可访问不属于漏洞，仅作信息收集。

## 二、快速开始

### A. 可视化 GUI 软件（推荐，双击即用）

打包产物：**`教育SRC挖洞工具.exe`**（约91MB，**图形界面软件**，全功能内置）

**双击即打开图形窗口**，无需命令提示符、无需 Python、无任何伴随文件：
- 顶部：搜索目标学校（如 `北京`、`zju`、`清华`），下拉选择
- 中部按钮：**①资产收集 → ②漏洞挖掘 → ③复测 → ④生成报告**，以及 **▶一键全流程**、**■停止**
- 多标签页实时展示：资产（子域名/存活）、漏洞发现、Nday线索、运行日志、**报告管理**
- 报告管理页：报告**自动缓存登记**，支持刷新/查看内容/打开/重命名/删除，双击即可查看
- 底部进度条与阶段状态，**■停止** 可随时中止

> - 单文件，双击即用。全程图形化，无需命令行。
> - 结果固定写 `e:\trae自动化\edu-src-toolkit\outputs\`（E盘，绝不写C盘）。
> - 报告生成后自动登记进「报告管理」，可随时查看/打开/删除。

### B. 源码版（开发用）

```powershell
# 图形界面版（源码运行）
E:\python3.14.6\python.exe gui_app.py

# 命令行版（可选）
python run.py                    # 交互选校 + 全流程
python run.py -s zju             # 指定学校全流程
python run.py --list             # 列出学校
python run.py --search 广东      # 搜索
```

### C. 重新打包 exe

```powershell
E:\python3.14.6\python.exe -m pip install pyinstaller
cd e:\trae自动化\edu-src-toolkit
E:\python3.14.6\python.exe -m PyInstaller --noconfirm edu_src_gui.spec
# 图形界面单文件产物在 dist\教育SRC挖洞工具.exe
```

## 三、本地漏洞库对接（D盘）

工具自动读取你的两个库：

| 库 | 路径 | 用途 |
|----|------|------|
| 批量CVE/CNVD | `D:\CVE`（含 `CNVD\cnvd.parquet`） | Web指纹 → Nday候选匹配 |
| PoC源码库 | `D:\漏洞库\exploitarium` | 漏洞类型 → 本地检测脚本关联 |

**parquet 依赖**（读取CNVD全量库需要）：
```powershell
pip install pyarrow pandas
```
未安装时工具自动降级（仅用 cve_to_cnvd.json 的CVE-CNVD映射，不匹配描述）。

## 四、外部工具（可选加速）

工具会自动探测并调用 `F:\One-fox\tools`（或 PATH）下已安装的扫描器，
覆盖全部渗透手法，任一工具缺失/异常自动降级、不中断全流程：

| 工具 | 用途 |
|------|------|
| `nuclei` | 模板扫描：Web/中间件/框架/CVE 全漏洞类型 |
| `afrog` | 配置/漏洞类 PoC 扫描 |
| `ehole` / `P1finger` | 资产指纹识别（精确匹配Nday） |
| `fscan` | 端口/服务/常见弱口令、未授权（攻击面补充） |
| `xray` | 综合引擎：XSS注入/任意跳转/SSRF/SQLi/命令注入/路径穿越等 |
| `httpx` | 探活/指纹 |
| `sqlmap` | SQL注入深度自动验证（离线增强） |

> 工具根目录默认 `F:\One-fox\tools`，可改 `src/recon/tooling.py` 的 `TOOLS_ROOT`。

## 五、目录结构

```
edu-src-toolkit/
├── run.py                   # 主入口
├── selfcheck.py             # 自检(模块导入/本地库索引)
├── integration_test.py      # 离线集成测试(不发真实请求)
├── data/
│   └── universities.py      # 高校数据库(可自行增删)
├── src/
│   ├── config.py            # 配置(D盘路径/工具检测)
│   ├── selector.py          # 选校交互
│   ├── recon/
│   │   ├── asset_collector.py  # 子域名枚举
│   │   ├── prober.py           # 探活+指纹
│   │   └── tooling.py          # 外部扫描器联动(nuclei/afrog/ehole/fscan/xray)
│   ├── vuln/
│   │   ├── engine.py           # 漏洞挖掘引擎(被动+主动+外部扫描统编，含CNVD Nday匹配)
│   │   ├── evidence.py         # 敏感文件证据链判定
│   │   ├── nday_verify.py      # Nday特征验证(shiro/spring/反序列化入口等)
│   │   └── poc_index.py        # exploitarium PoC索引
│   ├── exploit/                # 【新增】主动漏洞验证引擎
│   │   ├── vectors.py          #   输入向量提取(URL/表单/链接参数)
│   │   ├── checks.py           #   SQLi/XSS/路径穿越/开放重定向判定器
│   │   └── engine.py           #   攻击编排 + attack_log 还原
│   ├── reverify.py          # 复测(泄露二次取证 / 主动漏洞重跑判定器)
│   └── report/
│       ├── generator.py     # 报告生成(PTES七阶段完整报告)
│       └── manager.py       # 报告管理器(缓存+增删改查+路径/打开/查看)
└── outputs/
    ├── reports/              # 报告统一缓存目录
    ├── reports_registry.json # 报告索引(CRUD登记)
    └── <学校代码>/          # 每校独立输出
```

## 六、注意事项

1. **红线**：所有输出只在 E 盘 `outputs/` 下，不写 C 盘。
2. 复测与敏感探测均为**无害识别**，不含破坏性利用。
3. Nday候选仅作**线索提示**，需人工核对真实版本与授权范围后再决定是否验证。
4. 报告生成后会在「报告管理」中自动缓存，**删除仅移除缓存副本**，不影响原始报告；上报前请人工审核。