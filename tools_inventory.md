# F:\One-fox\tools 工具清单与 SRC 挖洞价值评估

## 一、已集成（核心扫描器）

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| nuclei | gui_scan\nuclei\nuclei.exe | 模板扫描，覆盖全漏洞类型 | ★★★★★ |
| afrog | gui_other\afrog\afrog.exe | PoC漏洞扫描 | ★★★★★ |
| xray | gui_other\xray\xray.exe | 综合漏洞扫描(XSS/SQLi/SSRF等) | ★★★★★ |
| ehole | gui_scan\dirsearch\ehole\ehole.exe | 资产指纹识别 | ★★★★☆ |
| P1finger | gui_scan\P1finger\P1finger64.exe | 资产指纹识别 | ★★★★☆ |
| fscan | gui_scan\fscan\fscan.exe | 端口服务扫描/弱口令 | ★★★★☆ |
| httpx | gui_scan\fcke\httpx.exe | 探活/指纹 | ★★★★☆ |
| sqlmap | gui_scan\sqlmap-master\sqlmap.py | SQL注入深度验证 | ★★★★☆ |
| oneforall | gui_shouji\oneforall\oneforall.py | 子域名收集 | ★★★★☆ |

## 二、待集成（高价值 SRC 工具）

### 2.1 信息收集增强

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| TscanPlus | gui_scan\tscanplus\TscanPlus_Win_Amd64.exe | 综合信息收集(端口/服务/指纹) | ★★★★★ |
| xscan | gui_scan\xscan\xscan.exe | 端口扫描/漏洞检测 | ★★★★☆ |
| RustScan | gui_scan\RustScan-master | 高速端口扫描 | ★★★★☆ |
| kscan | gui_other\kscan\kscan_windows_amd64.exe | 资产收集/指纹识别 | ★★★★☆ |
| enscan | gui_other\enscan\enscan-v1.2.2-windows-amd64.exe | 企业信息收集(ICP/备案/子公司) | ★★★★☆ |
| Railgun | gui_other\gorailgun\Railgun.exe | 自动化信息收集 | ★★★★☆ |
| massdns | gui_shouji\oneforall\massdns.exe | 高速DNS爆破(子域名) | ★★★★☆ |
| fofaviewer | gui_shouji\fofaviewer\MultiplePupils.exe | FOFA资产测绘 | ★★★☆☆ |
| Fine | gui_shouji\fine\Fine_windows_amd64.exe | 子域名/目录收集 | ★★★☆☆ |
| golin | gui_shouji\golin\golin.exe | 信息收集 | ★★★☆☆ |
| goon | gui_shouji\goon\goon3_win_amd64.exe | 信息收集 | ★★★☆☆ |

### 2.2 中间件/框架漏洞验证（Nday利用）

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| shiro_attack | gui_scan\shiro\shiro_attack-4.7.0-SNAPSHOT-all.jar | Shiro反序列化利用 | ★★★★★ |
| shiroPoc | gui_scan\shiro\Pyke-Shiro_0.3.jar | Shiro漏洞验证 | ★★★★★ |
| JNDIExploit | gui_other\JNDIE2.5\JNDI-Injection-Exploit-Plus-2.5-SNAPSHOT-all.jar | JNDI注入利用(Log4j/Fastjson) | ★★★★★ |
| ysoserial | gui_scan\yso\ysoserial.jar | Java反序列化Payload生成 | ★★★★★ |
| WeblogicTool | gui_scan\weblogic\WeblogicTool_1.3.jar | WebLogic漏洞利用 | ★★★★★ |
| ThinkphpGUI | gui_scan\thinkphp\ThinkphpGUI.jar | ThinkPHP漏洞利用 | ★★★★☆ |
| struts2_19 | gui_scan\struts2\struts2_19.jar | Struts2漏洞利用 | ★★★★☆ |
| NacosExploit | gui_scan\nacos\NacosExploit-1.0.1-SNAPSHOT-jar-with-dependencies.jar | Nacos漏洞利用 | ★★★★☆ |
| JenkinsExploit | gui_scan\jenkins\JenkinsExploit-GUI-1.3-SNAPSHOT.jar | Jenkins漏洞利用 | ★★★★☆ |
| XXL-JOB工具 | gui_scan\xxljob\XXL-JOB漏洞综合利用工具_1.5.jar | XXL-JOB漏洞利用 | ★★★★☆ |
| jeecgExploitss | gui_scan\jeecg\jeecgExploitss.jar | JeecgBoot漏洞利用 | ★★★★☆ |
| RuoYiVueScan | gui_scan\Ruoyi-All-master\RuoYiVueScan-v7.exe | 若依漏洞扫描 | ★★★★☆ |
| redis-rogue-server | gui_scan\redis-rogue-server\redis.exe | Redis未授权利用 | ★★★★☆ |
| postgreUtil | gui_scan\postgre\postgreUtil-1.0-SNAPSHOT-jar-with-dependencies.jar | PostgreSQL漏洞利用 | ★★★☆☆ |
| Hikvision工具 | gui_scan\hikvision\hikvision.exe | 海康威视摄像头漏洞 | ★★★☆☆ |
| VcenterKit | gui_other\vcenterKit\VcenterKit.py | vCenter漏洞利用 | ★★★☆☆ |

### 2.3 Web漏洞专项

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| SuperSQLInjection | gui_scan\supersql\SuperSQLInjection.exe | SQL注入图形化工具 | ★★★★☆ |
| weekoa | gui_scan\OAexp\weekoa.exe | OA系统弱口令 | ★★★★☆ |
| JDumpSpiderGUI | gui_scan\heapdump\JDumpSpiderGUI-1.0-SNAPSHOT-full.jar | HeapDump敏感信息提取 | ★★★★☆ |
| WebCrack | gui_scan\WebCrack-master\2024-03-14-0.1.2-win-x64.exe | Webpack源码解包 | ★★★★☆ |
| webpackscan | gui_scan\webpackscan\ | Webpack源码泄露扫描 | ★★★★☆ |
| DecryptTools | gui_scan\decrypt\DecryptToolsV3.0.jar | 各种加密解密工具集 | ★★★☆☆ |
| mitan | gui_scan\mitan\mitan-jar-with-dependencies.jar | 密文分析 | ★★★☆☆ |
| JUBILANT-WOLF | gui_scan\weekpasswd\JUBILANT-WOLF-V2.0.1.exe | 弱口令扫描 | ★★★☆☆ |
| JsonExp | gui_scan\json\JsonExp.exe | JSON注入 | ★★★☆☆ |
| vue_scan | gui_scan\vuescan\vue_scan.exe | Vue源码泄露扫描 | ★★★☆☆ |
| HeartsK | gui_scan\heartsk\HeartsK.exe | 信息收集 | ★★★☆☆ |
| Aazhen | gui_scan\Aazhen-v3.1-main\Aazhen_Scanner_V3.1.exe | 综合扫描器 | ★★★☆☆ |
| API-T00L | gui_scan\apitool\API-T00L_v1.2.jar | API接口测试 | ★★★☆☆ |
| aksktool | gui_scan\aksk\aksktool.jar | AK/SK密钥泄露检测 | ★★★☆☆ |
| DockerAPITool | gui_scan\docker\DockerAPITool_v0.1.jar | Docker API未授权 | ★★★☆☆ |
| pppscan | gui_scan\pppscan\pppscan.exe | PPP扫描 | ★★☆☆☆ |

### 2.4 目录/敏感文件扫描

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| dirscan | gui_shouji\dirscan_3.0\scandir-3.0.jar | 目录扫描 | ★★★★☆ |
| 御剑 | gui_shouji\yjdirscanv1.1\御剑2.exe | 目录扫描(经典) | ★★★☆☆ |
| bjx | gui_shouji\bjx11\bjx.exe | 目录扫描 | ★★★☆☆ |
| Polarscan | gui_shouji\bjx11\Polarscan.exe | 扫描器 | ★★★☆☆ |

### 2.5 内网渗透（SRC辅助，主要用于验证后渗透路径）

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| mimikatz | gui_other\mimikatz\mimikatz.exe | 凭据提取 | ★★★☆☆ |
| Ladon | gui_other\ladon\Ladon.exe | 内网综合渗透 | ★★★☆☆ |
| frp | gui_other\frp\frpc.exe | 内网穿透 | ★★★☆☆ |
| suo5 | gui_other\suo5\suo5-windows-amd64.exe | HTTP隧道 | ★★☆☆☆ |
| pingtunnel | gui_other\pingtunnel\pingtunnel.exe | ICMP隧道 | ★★☆☆☆ |
| goexec | gui_other\goexec\goexec.exe | 命令执行 | ★★☆☆☆ |
| Webshell_Generate | gui_other\webshellsc\Webshell_Generate-1.2.4.jar | Webshell生成 | ★★☆☆☆ |

### 2.6 Webshell管理（人工操作，非自动化）

| 工具 | 路径 | 用途 | SRC价值 |
|------|------|------|---------|
| AntSword | gui_webshell\alien | 蚁剑 | ★★☆☆☆ |
| Behinder | gui_webshell\Behinder4 | 冰蝎 | ★★☆☆☆ |
| Godzilla | gui_webshell\Godzilla | 哥斯拉 | ★★☆☆☆ |

### 2.7 Burp插件（被动扫描增强）

| 插件 | 用途 | SRC价值 |
|------|------|---------|
| BurpFastJsonScan | Fastjson被动检测 | ★★★★☆ |
| BurpShiroPassiveScan | Shiro被动检测 | ★★★★☆ |
| BurpLog4j2Scan | Log4j被动检测 | ★★★★☆ |
| Log4j2Scan | Log4j扫描 | ★★★★☆ |
| SpringScan | Spring漏洞扫描 | ★★★★☆ |
| RouteVulScan | 路径遍历扫描 | ★★★☆☆ |
| TsojanScan | 综合扫描 | ★★★☆☆ |
| JWT4B | JWT测试 | ★★★☆☆ |
| sqlmap4burp++ | SQL注入 | ★★★☆☆ |
| HaE | 高亮提取 | ★★★☆☆ |
| BurpCrypto | 加解密 | ★★☆☆☆ |
| autoDecoder | 自动编解码 | ★★☆☆☆ |
| BurpBountyPro | 主动扫描增强 | ★★★☆☆ |
| LoggerPlusPlus | 日志增强 | ★★☆☆☆ |
| passive-scan-client | 被动扫描 | ★★☆☆☆ |
| chunked-coding-converter | Chunked编码 | ★★☆☆☆ |
| HackBar | 测试辅助 | ★★☆☆☆ |

## 三、集成优先级建议

### 第一优先级（立即集成，SRC命中率提升最大）

1. **TscanPlus** - 综合信息收集，端口+服务+指纹一体化
2. **shiro_attack / shiroPoc** - Shiro反序列化验证（教育行业常见）
3. **JNDIExploit** - Log4j/Fastjson JNDI注入验证
4. **ysoserial** - Java反序列化Payload生成
5. **WeblogicTool** - WebLogic漏洞（教育行业常见中间件）
6. **ThinkphpGUI** - ThinkPHP漏洞（教育行业常见框架）
7. **JDumpSpiderGUI** - HeapDump敏感信息提取
8. **WebCrack** - Webpack源码泄露扫描
9. **dirscan** - 目录扫描
10. **kscan** - 资产收集增强

### 第二优先级（后续集成）

- NacosExploit, JenkinsExploit, XXL-JOB工具, jeecgExploitss
- RuoYiVueScan, redis-rogue-server
- SuperSQLInjection, weekoa
- Railgun, enscan
- Burp插件集成（需要Burp运行环境）

### 不集成（原因）

- **Webshell管理工具** - 需要人工操作，不适合自动化
- **内网渗透工具** - SRC主要是外网，内网渗透超出范围
- **手机安全工具** - 教育SRC主要是Web资产
- **部分小众工具** - 使用频率低，维护成本高

## 四、集成方式

```python
# src/recon/tooling.py 扩展
TOOL_PATHS = {
    # 已有
    "nuclei": r"gui_scan\nuclei\nuclei.exe",
    "afrog": r"gui_other\afrog\afrog.exe",
    "xray": r"gui_other\xray\xray.exe",
    "ehole": r"gui_scan\dirsearch\ehole\ehole.exe",
    "fscan": r"gui_scan\fscan\fscan.exe",
    "httpx": r"gui_scan\fcke\httpx.exe",
    "sqlmap": r"gui_scan\sqlmap-master\sqlmap.py",
    "oneforall": r"gui_shouji\oneforall\oneforall.py",
    
    # 新增 - 信息收集
    "tscanplus": r"gui_scan\tscanplus\TscanPlus_Win_Amd64.exe",
    "xscan": r"gui_scan\xscan\xscan.exe",
    "kscan": r"gui_other\kscan\kscan_windows_amd64.exe",
    "railgun": r"gui_other\gorailgun\Railgun.exe",
    
    # 新增 - 漏洞验证（按需调用）
    "shiro_attack": r"gui_scan\shiro\shiro_attack-4.7.0-SNAPSHOT-all.jar",
    "jndi_exploit": r"gui_other\JNDIE2.5\JNDI-Injection-Exploit-Plus-2.5-SNAPSHOT-all.jar",
    "ysoserial": r"gui_scan\yso\ysoserial.jar",
    "weblogic_tool": r"gui_scan\weblogic\WeblogicTool_1.3.jar",
    "thinkphp_gui": r"gui_scan\thinkphp\ThinkphpGUI.jar",
    "jdump_spider": r"gui_scan\heapdump\JDumpSpiderGUI-1.0-SNAPSHOT-full.jar",
    "webcrack": r"gui_scan\WebCrack-master\2024-03-14-0.1.2-win-x64.exe",
    "dirscan": r"gui_shouji\dirscan_3.0\scandir-3.0.jar",
}
```

## 五、总结

你的工具库约有 **180+ 个工具**，其中：
- **已集成**: 9 个核心扫描器
- **高价值待集成**: 约 30 个（第一优先级10个 + 第二优先级20个）
- **可集成但价值有限**: 约 50 个（内网渗透、手机安全等）
- **不适合自动化**: 约 90 个（Webshell管理、Burp插件、辅助工具等）

**SRC挖洞真正有用的约 40-50 个工具**，核心是：
1. 信息收集（子域名/端口/指纹）
2. Web漏洞扫描（nuclei/afrog/xray）
3. 中间件漏洞验证（Shiro/WebLogic/ThinkPHP/Struts2）
4. 敏感信息泄露（HeapDump/Webpack/源码泄露）
5. 目录扫描

建议先集成第一优先级的 10 个工具，可显著提升 SRC 命中率。
