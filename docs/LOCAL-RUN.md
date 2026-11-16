# 本地执行手册（Windows 10）

这台机器上怎么把 wifit3 跑起来、怎么验证、怎么留证、出错怎么办。

- 适用：仓库克隆后的日常开发与自测，操作系统 Windows 10。
- 位置：所有命令都在**仓库根目录**执行（`F:\haha-work\WIFIT3解密`）。
- 写法：示例用 cmd / PowerShell 的反斜杠；Git Bash 里把 `\` 换成 `/`。
- 所有命令都要求走 `.venv` 里的解释器，不要用系统 Python。

本文所有数字与输出均为 2026-11-16 在本机实测，不是推测。

---

## 0. 一分钟版

```bat
:: 改动有没有坏东西
.venv\Scripts\python.exe scripts\one_click_test.py --include-slow

:: 这台机器的射频能不能注入
.venv\Scripts\python.exe -m wifit3 --capabilities

:: 产品链路是否端到端成立
.venv\Scripts\python.exe scripts\verify_design_intent.py --psk-file .secrets\enhua_a.psk
```

（`::` 在 cmd 里只有**行首**才是注释。写在同一行的命令后面会被当成参数传进去，所以注释一律单独占一行。）

---

## 1. 环境

| 项 | 值 |
|---|---|
| 解释器 | `.venv\Scripts\python.exe`（仓库自带，已就绪） |
| Python | `requires-python = ">=3.11"`，本机 3.12.13 |
| 依赖管理 | Astral `uv`（与 CI 一致） |
| 版本自检 | `.venv\Scripts\python.exe -m wifit3 --version` → `wifit3 0.7.1` |

环境丢了或换机时重建（与 `.github/workflows/ci.yml` 同一条命令）：

```bat
uv sync --group dev
```

`--group dev` 不能省。省掉就没有 `pytest` / `ruff` / `pyinstaller`，下面大半命令都跑不了。

---

## 2. 本地门禁：一条命令跑完

```bat
scripts\run-all.cmd
```

双击也行。它先打印**运行环境**（仓库根目录、Python 绝对路径、虚拟环境、版本、实际被 import 的 `wifit3` 目录，以及设置了的话还有 `PYTHONPATH`），再问一句**要不要用自己的 SSID/BSSID 实测**（30 秒不答按 N），然后调用 `one_click_test.py`，最后打印「全部通过 / 通过但有暂停项 / 存在失败阶段」、`pause` 住让你看结果，退出码透传。

环境那几行是有用的：`wifit3` 目录若不在本仓库的 `src\` 下，说明跑的不是这份代码（editable 安装指向别处，或有 `PYTHONPATH` 抢先）。

等价的手动调用与耗时（本机实测）：

| 命令 | 耗时 | 跑什么 | 用途 |
|---|---|---|---|
| `... one_click_test.py` | 88 s | 环境 / ruff / 指纹库 / pytest 全量 / 设计意图链 | 提交前 |
| `... one_click_test.py --fast` | 18 s | 只跑改动涉及的核心子集（678 用例） | 改一行就想知道有没有炸 |
| `... one_click_test.py --include-slow` | +50 s | 连 `@pytest.mark.slow` 一起（WEP 端到端） | 动过 WEP / 加密相关 |
| `... one_click_test.py --no-lint` | 省 0.5 s | 跳过 `ruff check` | 极少用 |

其余开关：`--no-tests` / `--no-verify` / `--no-smoke` / `--progress {plain,bar,none}` / `--ask-targets` / `--debug-plaintext [路径]`。
后两个见第 3 节的「换目标」与「调试开关」。

**输出长什么样**（下面是 `--fast` 的全部通过形态，实测）：

```
  #   阶段                      结果       耗时   说明
  1   环境自检                  PASS       1.7s   一切就绪
  2   静态检查（ruff）          PASS       0.5s   全部通过
  3   指纹库自检                PASS       0.9s   58407 条 OUI
  4   回归测试（pytest）        PASS      11.5s   678 passed in 8.8s
  5   设计意图验证              PASS       3.2s   16/16 步通过
------------------------------------------------------------------------------
      总计                      PASS      18.0s
```

不带 `--fast` 时第 4 行会变成全量（约 81 s、5100+ 用例），总计约 88 s，且**会看到下面那两条既有红**。日志落在 `logs\<日期>-一键测试.log`。

若 `dist\` 下已有打包产物，脚本会**自动追加**一阶段，对真实二进制跑 `--smoke`（见第 7 节）。

**两条纪律**：

1. `--fast` 不是发布门禁。脚本自己会在末尾提示这一点，别把它的绿色当成可以发布的依据。
2. 全量跑出现这两个红，是**既有失败**，不计入本轮改动：
   - `tests/chips/rtl8188ftv_dkms/test_driver.py::test_watchdog_loop_skips_faulty_tick`（HEAD 即失败）
   - `tests/campaigns/test_wps_association.py::test_falls_back_to_assoc_when_no_auth_resp`（0.05 s 超时撞 Windows 15.6 ms 计时粒度，多次实测多数时候通过、偶尔红；已用干净 worktree 证明 HEAD 同样会红，样本不大，不作精确概率声明）
   - `tests/chips/sim/test_product_journey.py::test_the_journey_measures_link_acks_on_the_deauth_path`（异步数 ACK，负载下可能少计一轮。实测：隔离单跑 8/8 通过、fast 子集直跑 3/3 通过，仅在 one_click 子进程负载下见过 1 次失败；不是本轮改动引入，但也没修，先记在这里）

---

## 3. 设计意图验证：留证用

它不替代 pytest。pytest 回答「函数对不对」，这条链回答「产品链路在无硬件前提下是否真的跑通，且每一步都能解释」。

```bat
:: 单网络
.venv\Scripts\python.exe scripts\verify_design_intent.py --psk-file .secrets\enhua_a.psk

:: 多网络：第三段是该设备自己的口令文件，省略则回退到 --psk-file
.venv\Scripts\python.exe scripts\verify_design_intent.py ^
  --target "Enhua_a:90:76:9f:ae:8d:e8:.secrets\enhua_a.psk" ^
  --target "enhua:24:f6:03:27:76:cc:.secrets\enhua.psk"

:: 只想核对用的是哪份口令，不想把口令交出去
.venv\Scripts\python.exe scripts\verify_design_intent.py --psk-file .secrets\enhua_a.psk --fingerprint
```

（上面是 cmd 写法，续行符 `^`；PowerShell 用反引号，Git Bash 用 `\`。）

`--fingerprint` 只打印 `sha256[:12]`，比对的是「口径一致」而不是「口令一致」，所以可以贴给别人看。

**进度显示四档**，默认 `auto`（终端里画条，重定向时自动关掉）：

| 值 | 行为 | 用在哪 |
|---|---|---|
| `auto` | 有 TTY 才画条 | 手动跑 |
| `bar` | 强制画条 | 想录屏 |
| `plain` | 只输出百分比行 | 被别的脚本接管输出时 |
| `none` | 关闭 | CI / 日志采集 |

**产物**（两个文件，一一对应）：

| 文件 | 内容 |
|---|---|
| `logs\<日期>-设计意图验证.jsonl` | 每步一行，字段 `ts / step / title / intent / action / expected / actual / ok / verdict / detail / elapsed_ms / progress` |
| `logs\<日期>-设计意图验证.log` | 同上的中文可读版，含效率统计表 |

`ok` 有三个取值，不是两个：`true` 通过、`false` 失败、`null` **暂停**（`verdict: "suspended"`，见下面的调试开关）。

本机一次完整跑：**16 步 / 全 PASS / 端到端 2.3 s**，日志自报「进度计划 16/16 一致」。这个一致性是脚本自己断言的，不是人眼数的。

**退出码**：`0` 全通过、`3` 没有失败但有步骤暂停、`1` 有失败、`2` 还没干活就拒绝了（例如缺口令）。`3` 是刻意与 `0` 分开的——「没有失败」不等于「干净通过」，包装脚本才有机会把这句话重复一遍而不是盖过去。

### 换目标：不想维护 `targets.txt` 就手输

```bat
.venv\Scripts\python.exe scripts\verify_design_intent.py --psk-file .secrets\enhua_a.psk --ask-targets
```

逐条问 SSID / BSSID / 口令文件路径，BSSID 随便怎么写（`24-f6-03…`、`24f603…` 都收，统一成冒号形式）。三个细节值得知道：

- **仍然只输路径，不输口令本身**。提示里打口令会进终端回滚缓冲，和写在命令行上一个性质。
- 输入时就会和 `netsh wlan show interfaces` 的当前关联对账。BSSID 正是本机连着的那个、SSID 却填了别的名字，当场提醒——比等到第 13 步才发现早得多。
- 标准输入不是终端时**直接拒绝**（`--ask-targets 需要交互式终端`）。管道会立刻读到 EOF，产出「零个目标」的假绿，看起来和「没东西可查」一模一样。

`run-all.cmd` 里回答 Y 就是带着这个开关跑。

### 调试开关：把明文写出来（默认关）

```bat
.venv\Scripts\python.exe scripts\verify_design_intent.py --psk-file .secrets\enhua_a.psk ^
  --target "enhua:24:f6:03:27:76:cc" --debug-plaintext
```

默认写 `.\logout.txt`，也可以自己给路径。内容是**指纹到明文的对照**加**派生出的 PMKID**：

```
# 口令：指纹 -> 明文
sha256[:12]=81d51827b5a2  ssid=demo-net  bssid=24:f6:03:27:76:cc  psk=<明文>
# 派生 PMKID：可直接喂 hashcat -m 22000
ssid=demo-net  bssid=24:f6:03:27:76:cc  sta=02:99:fa:94:70:aa  pmkid=<16 字节>
```

为什么需要它：日志只留 `sha256[:12]` 指纹，而指纹只能向「已经有口令的人」证明用的是哪份口令。真要事后核对，就得有明文。

**打开后发生什么**（这是重点）：

- 第 15 步「密钥不落地」变成 **SUSPENDED**，不是 PASS。要求本身没被违反，是**本轮不再执行这条要求**，所以不能报绿。
- 汇总里出现「本轮 1 项暂停，既不算通过也不算失败」「本轮结论 PASS（含 1 项暂停，非干净通过）」，退出码是 **3**；`one_click_test.py` 记作 `PASS*`，`run-all.cmd` 打印「通过，但有断言按调试开关暂停」。
- 日志本身**仍然照扫**。开关只豁免我们故意写的那份文件，不豁免日志：日志要是漏了明文，这一步照样判 FAIL。
- 给的是仓库内路径而 `.gitignore` 没覆盖它，会在备注里点出来；`.\logout.txt` 已被 `.gitignore` 覆盖（`/logout.txt`、`/logout*.txt`）。
- **核对完请删掉**。这个文件等于一份可直接离线爆破的 hash 加上它的口令。

| `--debug-plaintext` | 第 15 步 | 退出码 | 含义 |
|---|---|---|---|
| 不给 | PASS（真扫描过） | 0 | 干净通过 |
| 给，且本轮有口令 | SUSPENDED | 3 | 跳过该断言，明文在 `logout.txt` |
| 给，但本轮没口令 | PASS | 0 | 没有可写的明文，照常断言 |
| 给，且日志真漏了明文 | FAIL | 1 | 泄漏优先，不因开关而豁免 |

### 口令规矩（红线）

- **口令永不出现在命令行上**。理由不是洁癖：argv 会进 shell 历史、进 `ps` / 任务管理器、进崩溃转储、进子进程环境。
- 只有三种来源：`--psk-file <路径>`（推荐）、`--psk-stdin`、`--psk-prompt`（无回显）。
- 日志里只有 `sha256[:12]` 指纹，明文、小写 hex、大写 hex 都不落盘。
- 每次跑完会做一次**字节级回读扫描**：把日志按字节读回来，搜两份口令的三种形式加派生出的 PMKID，命中就把日志清空并判 FAIL。所以「不会写进日志」是可执行断言，不是口头承诺。**唯一例外是 `--debug-plaintext`**：那条路把明文写到你自己指定的文件，扫描这步转为暂停而不是通过，见下面「调试开关」。
- 口令文件放 `.secrets\`，该目录被 `.gitignore:42` 的 `.*` 覆盖，不会误提交。
- 口令请用**真实的 8-63 字符**值。拿一个 1-2 字符的假口令跑，泄漏扫描按子串比对会命中文档里的普通字符，于是报 `命中明文` 判 FAIL，指纹也不再不可逆；脚本会先打一行提示说明这件事，别把它当成真泄漏。

---

## 4. 指纹库离线解锁

```bat
.venv\Scripts\python.exe scripts\id\local_fingerprint.py stats
.venv\Scripts\python.exe scripts\id\local_fingerprint.py lookup 24:f6:03:27:76:cc 90:76:9f:ae:8d:e8
.venv\Scripts\python.exe scripts\id\local_fingerprint.py dump --format csv --out vendors.csv
.venv\Scripts\python.exe scripts\id\local_fingerprint.py gaps captures logs
```

纯本地读取：不联网、不开射频、不发起任何发送。

| 子命令 | 回答什么 | 本机实测 |
|---|---|---|
| `stats` | 库有多大、规则覆盖多少 | 58,407 条（24 位 40,070 / 28 位 6,575 / 36 位 11,762），33,234 个厂商名，33,197 个归一化品牌；37 条品牌规则（按 OUI 直指 6 / 按厂商名正则 31），覆盖 72 个 OUI，最大一条 Roku 占 31 个 |
| `lookup` | 某个 MAC 是谁 | `24:f6:03:27:76:cc` → Huawei Technologies；`90:76:9f:ae:8d:e8` → Mercury Communication Technologies |
| `dump` | 全表导出，供外部 diff | CSV / JSON |
| `gaps` | 采集与日志里有哪些地址不在库里 | 真实盲区 0 |

`gaps` 有一个必须先懂的点：`02:` 开头的地址是**本地管理地址**（首字节 `0x02` 位被置位），按规范永远不在 IEEE 注册表里，所以它不是「库里缺了」，而是「本来就不该有」。脚本已经滤掉这类地址，报告里说"真实盲区 0"是这个意思。早期版本没滤，会把采集里的一批随机 MAC 全报成盲区。

`stats` 在本机要 14 s 左右（大表加规则收敛计算），`lookup` 是秒级。要更快地只查条目数，绕开 `stats`：

```bat
.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'src'); from wifit3.id import VENDOR_BY_OUI as v; print(len(v))"
```

---

## 5. 这台机器的射频能力（CLI + 面板）

```bat
:: 文本报告
.venv\Scripts\python.exe -m wifit3 --capabilities

:: 机器可读
.venv\Scripts\python.exe -m wifit3 --capabilities json

:: 只要一行摘要
.venv\Scripts\wifit3-capabilities.exe --quiet
```

退出码 `0` 表示有可用适配器，`1` 表示一个都没有。脚本可以据此判「这台机器到底有没有卡」，因为「打印成功」不等于「有东西可用」。

判定值含义（`--capabilities` 与面板同一套）：

| verdict | 含义 |
|---|---|
| `injection_capable` | 有 monitor 模式且有原始发送，全套战役可跑 |
| `passive_only` | 只能抓，不能发（例如 iwlwifi 的 passive monitor） |
| `firmware_refused` | 驱动和固件都正常，但能力被上报为不支持，用户态改不了 |
| `hardware_lacking` | 有卡但报不出 PHY 或能力集 |
| `driver_unsupported` | 没有接口，或没绑上驱动 |
| `unknown` | 系统没给出决定性信息 |

本机现状（Intel Wireless-AC 9462）：`firmware_refused`，同时 `8086:a0f0` 被识别为 CNVi、`reach=passive`，即「这块卡 wifit3 永远打不开，最多只能靠 Npcap 被动抓」。

图形界面里按 **Ctrl+R** 打开同一份数据的面板：`r` 重测、`y` 复制、`Esc` 关闭。「复制」拿到的是 CLI 的文本输出，逐字节相同，所以截图和粘出去的日志是同一份证据。

---

## 6. 直接跑测试

```bat
:: 默认排除 slow
.venv\Scripts\python.exe -m pytest

:: 只跑 slow（15 个，约 50 s）
.venv\Scripts\python.exe -m pytest -m slow

:: 单目录 / 单文件
.venv\Scripts\python.exe -m pytest tests\wlan -q
.venv\Scripts\python.exe -m pytest tests\test_host_profile.py -q
```

`slow` 为什么默认排除：PR 门禁要快，`pyproject.toml` 的 `addopts` 写死 `-m 'not slow'`。但 `slow` 里包含**整个仓库唯一的 WEP 端到端密钥恢复证据**，所以它不能消失，只能分层：夜间通道 + 发布闸门跑，PR 门禁不跑。

本机 Windows 10 有三个必须知道的行为差异：

1. **WEP 破解走 `ProcessPoolExecutor`**。Windows 是 `spawn`（每个 worker 重新 import 并 pickle），Linux 是 `fork`。`test_cracker_picklable_and_recovers_after_roundtrip` 存在的唯一目的就是盯这条 spawn 路径，它只在 Windows 上真的被测到。
2. **计时粒度 15.6 ms**。任何 50 ms 级的超时断言在 Windows 上天然不稳（第 2 节那条 flaky 就是这个原因）。新写带超时的用例请留够余量。
3. **`tests/ui/test_app_signals.py` 在 Windows 上整模块 skip**（POSIX signals only）。信号处理路径本机测不到，只有 ubuntu 上跑。

---

## 7. 打包与发布

```bat
.venv\Scripts\python.exe -m PyInstaller wifit3.spec --noconfirm --clean
dist\wifit3.exe --version
dist\wifit3.exe --smoke
```

产物是单文件 `dist\wifit3.exe`。`--smoke` 是无头自检（不启 TUI、渲染完就退），它检查三件事：绑定的 libusb 能加载、所有屏幕能挂载、`supported_ids()` 非空。

第三件事最容易被忽略也最致命：驱动靠 `pkgutil` 在运行时扫描发现，PyInstaller 静态分析看不见，所以 `wifit3.spec` 里必须 `collect_submodules("wifit3.chips")`。漏了它，程序**照样能启动**，只是驱动数为 0、界面上一个网卡都没有。`--smoke` 是唯一能抓住这个的检查。

发布（`__version__` 是唯一版本源，tag 必须与它一致）：

```bat
.venv\Scripts\python.exe scripts\release.py patch --push
```

推 `vX.Y.Z` tag 会触发 `.github/workflows/release.yml`，四平台构建 + `--smoke` + 发布资产。

四种形态各自能抓到的错不同，缺一不可：

| 形态 | 产物 | 只有它能抓到 |
|---|---|---|
| 源码运行 | 无 | 开发期即时反馈 |
| 回归测试 | 退出码 | 逻辑错，但抓不到端到端断裂 |
| 设计意图链 | `logs\*.jsonl` | 链路断在某一步（16 步逐步定位） |
| 单文件打包 | `dist\wifit3.exe` | 动态导入丢失（能启动但驱动为 0） |

---

## 8. 产物落点与命名

| 路径 | 内容 | 入库 |
|---|---|---|
| `.secrets\` | 口令文件、`targets.txt` | 否（`.gitignore:42` 的 `.*`） |
| `logs\` | 一键测试日志、验证链 jsonl/log | 否（`.gitignore:55`） |
| `captures\` | 抓包与 `.hc22000` | 否（`.gitignore:26`） |
| `dist\` | 打包产物 | 否（`.gitignore:23`） |

**日期型文件名必须带主题**：`YYYY-MM-DD-{主题}`，不允许纯日期。例如 `2026-11-16-一键测试.log`、`2026-11-16-设计意图验证.jsonl`。脚本按「日期前缀 + 类型后缀」glob 定位，所以主题可以改，前缀不能改。

---

## 9. 常见故障（都是本机踩过的）

**代理突然连不上**。`gh` / `curl` 报 `proxyconnect tcp: dial tcp 127.0.0.1:53357: connectex: 拒绝连接`，说明本机代理进程退出了。去掉代理直连即可：

```bat
set HTTP_PROXY=
set HTTPS_PROXY=
gh api repos/ikware99/wifit3/git/ref/heads/master
```

**`git push` 走不通**。SSH 可能报 `Could not resolve hostname github.com`，HTTPS 可能被代理 502 卡住。此时 `gh api` 通常仍可用，可走 Git Data API 重建提交（逐 blob 上传 → `base_tree` 建树 → `POST /git/commits` → `PATCH /git/refs`）。两个必须知道的坑：

- `base_tree` 必须是**树 SHA**（`git rev-parse <commit>^{tree}`），传 commit SHA 会 422；
- `parents` 必须是 **40 位完整 SHA**，短 SHA 同样 422。

**中文路径处理失败**。`git ls-tree` 默认把非 ASCII 路径转义成八进制，脚本匹配不到文件。所有 git 调用加 `-c core.quotepath=false`。

**`.cmd` 文件乱码**。`scripts\run-all.cmd` 必须是 **GB18030** 编码（`cmd.exe` 按系统代码页读），不要另存为 UTF-8，也不要加 `chcp 65001`。用 UTF-8 编辑器打开看到乱码是正常的，不代表文件坏了。

**改 `.cmd` 时 `for /f` 抓不到 Python 输出**。`for /f "delims=" %%v in ('"%PY%" -c "..."')` 会因为引号被重新解析，把命令截断成 `"...python.exe" -c "import`，报「不是内部或外部命令」。要么别用 `for /f`（直接让 Python 打印到控制台），要么走临时文件加 `set /p`。注意临时文件那条路只对纯 ASCII 安全：Python 重定向时写 UTF-8，`echo` 按控制台代码页输出，中文路径过一遍就变乱码。

**重定向后进度条变成 `####`**。不是坏了：`░` 在 CP936（中文 Windows 控制台/重定向）里无法编码，脚本检测到就自动降级成 `#` 和 `-`，否则会在收尾阶段抛 `UnicodeEncodeError` 把整轮结果吞掉。终端里仍是方块。

**改完日志出现 `\r`**。Windows 文本模式会把 `\n` 写成 `\r\n`，导致「无进度残留」这类断言失效。写日志必须显式 `newline="\n"`，判定要用字节计数：

```bat
.venv\Scripts\python.exe -c "import io; print(io.open('logs/x.log','rb').read().count(b'\r\n'))"
```

**`ruff check scripts\` 报 64 个错**。这是历史现状，`scripts\` 在 lint 闸门之外（闸门只管 `src\` 和 `tests\`）。新增文件自己保证干净即可，不要顺手全局改。

---

## 10. 相关文件

| 文件 | 作用 |
|---|---|
| `scripts\one_click_test.py` | 五阶段门禁，单一结论 |
| `scripts\run-all.cmd` | 上面那个的双击包装（GB18030） |
| `scripts\verify_design_intent.py` | 设计意图链，16 步逐步留证 |
| `scripts\id\local_fingerprint.py` | 指纹库离线读取（stats/lookup/dump/gaps） |
| `src\wifit3\host_profile.py` | 主机能力数据层（CLI 与面板共用） |
| `scripts\README.md` | 开发工具目录地图（按芯片分的 verify_pcap / test_hw 等） |
| `docs\planning\2026-11-16-wifit3全栈测试与代码审查.md` | 审查报告与第 8 节复核 |
