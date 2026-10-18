# WuSi_Encrypter

一个面向 Windows 的原生文件加密小工具：**图形界面 + 命令行双模式**，单文件 C++17 实现，静态链接、无运行时 DLL 依赖。

核心特点是**按比例原地加密**——不加密整个文件，而是把文件切成 1 MiB 的块，随机挑选其中一部分用 ChaCha20 就地异或，并为每个被加密的块附加 HMAC-SHA256 认证标签。加密后文件体积只增加少量元数据（每块 48 字节记录 + 36 字节尾部），解密时校验标签并还原，最后截断尾部。

> 适合快速遮蔽文件的关键内容，而不是替代 VeraCrypt / BitLocker 那样的全盘加密方案。

---

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [加密方案与文件格式](#加密方案与文件格式)
- [安全模型与限制](#安全模型与限制)
- [项目结构](#项目结构)
- [构建说明](#构建说明)
- [兼容性](#兼容性)
- [已知问题](#已知问题)
- [免责声明](#免责声明)

---

## 功能特性

- **比例加密**：1% ~ 100% 可调（默认 25%），随机抽取块，比例越低处理越快
- **逐块认证**：每个加密块带 HMAC-SHA256 标签，密码错误或文件被篡改会明确报错
- **密钥派生**：PBKDF2-HMAC-SHA256，10 万次迭代，每次加密生成随机盐
- **图形界面**：Win32 原生控件 + 自绘按钮、拖放添加文件、批量处理、实时日志
- **命令行模式**：可脚本化批量调用，密码隐藏输入、支持 `-p` 直接传入
- **单文件分发**：`-municode -mwindows -static` 全静态编译，只依赖 Windows 系统 DLL
- **高 DPI 与外观**：Per-Monitor V2 DPI 感知，Win11 原生圆角窗口
- **无第三方依赖**：SHA-256 / HMAC / PBKDF2 / ChaCha20 均为源码内置实现

## 快速开始

### 直接运行预编译版本

双击 `WuSi_FileEncryptor.exe` 即可启动图形界面。

仓库内的 `WuSi_FileEncryptor.exe` 与构建脚本输出的 `WuSi_Encrypter.exe` 是同一程序的同一份构建产物，仅文件名不同；两者任选其一使用即可。

### 从源码构建

环境要求：**MinGW-w64（x86_64, SEH），g++ 8.1.0 或更新**，`windres` 可用并已加入 `PATH`。

```bat
build.bat
```

脚本会先编译图标资源，再以 C++17 静态链接生成 `WuSi_Encrypter.exe`。也可以手动执行：

```bat
windres.exe resource.rc -O coff -o resource.o
g++.exe -std=c++17 -O2 -s -municode -mwindows ^
    -static -static-libgcc -static-libstdc++ ^
    -o WuSi_Encrypter.exe main.cpp resource.o ^
    -lcomctl32 -lshell32 -lole32 -luuid -lgdi32
```

## 使用说明

### 图形界面

1. 在「密码」输入框中输入密码（可勾选「显示密码」核对）
2. 设置「加密比例」：1 ~ 100，表示随机加密的 1 MiB 块占比，默认 25
3. 点击「添加文件」（可多选）或直接把文件拖进窗口
4. 点击「加密」或「解密」，在下方的日志区查看每个文件的结果

界面操作补充：

- 列表支持多选；「移除」删除选中项，「清空」清空整个列表，选中后按 `Delete` 也可删除
- 解密使用与加密**完全相同**的密码；密码错误会提示「认证失败（密码错误或文件损坏）」
- 比例参数只在加密时生效，解密时忽略

### 命令行

```
WuSi_Encrypter.exe                         启动图形界面
WuSi_Encrypter.exe enc [-r 比例] [-p 密码] 文件...
WuSi_Encrypter.exe dec [-p 密码] 文件...
WuSi_Encrypter.exe gui                     显式启动图形界面
WuSi_Encrypter.exe <enc|dec> -h            查看内置帮助
```

| 参数 | 说明 |
| --- | --- |
| `enc` / `encrypt` | 加密模式 |
| `dec` / `decrypt` | 解密模式 |
| `-r`, `--ratio` | 加密比例，取值 1 ~ 100（默认 25），仅加密模式有效 |
| `-p`, `--password` | 直接指定密码；省略时交互式输入（不回显，加密需二次确认） |
| `-h`, `--help` | 打印用法后退出 |

示例：

```bat
:: 以 30% 的比例加密两个文件，交互式输入密码
WuSi_Encrypter.exe enc -r 30 secret.docx photo.jpg

:: 指定密码解密
WuSi_Encrypter.exe dec -p mypass data.bin

:: 全部 100% 加密（整个文件内容都会被改写）
WuSi_Encrypter.exe enc -r 100 -p mypass archive.zip
```

退出码：

| 退出码 | 含义 |
| --- | --- |
| `0` | 全部文件处理成功（`enc -h` 等帮助调用同样返回 0） |
| `1` | 参数错误、密码为空、未指定文件等用法问题 |
| `2` | 至少一个文件处理失败（文件被占用、密码错误、格式不符等） |

> ⚠️ 加密是**原地**进行的，不产生副本。首次使用请先拿测试文件或备份验证。

## 加密方案与文件格式

### 密钥派生

```
密码 (UTF-8) ──PBKDF2-HMAC-SHA256(盐 16B, 100000 次) ──▶ 64 字节
                                        ├─ encKey (前 32 字节)：ChaCha20 密钥
                                        └─ macKey (后 32 字节)：HMAC-SHA256 密钥
```

### 块加密流程

1. 文件按 `blockSize = 1 MiB` 切块，`totalBlocks = ceil(fileSize / blockSize)`
2. `encCount = clamp(round(totalBlocks × ratio), 1, totalBlocks)`
3. 随机洗牌后取前 `encCount` 个块索引，排序
4. 对每个选中块：
   - 生成 12 字节随机 nonce
   - `ChaCha20(encKey, nonce, counter=0)` 就地异或整块
   - `tag = HMAC-SHA256(macKey, 块索引LE32 ‖ salt ‖ nonce ‖ 密文块)`（encrypt-then-MAC）
5. 追加尾部元数据，写入文件末尾

### 文件布局

```
[ original data ][ record 0 ][ record 1 ] ... [ record N-1 ][ fixed footer ]
   originalSize     48 bytes each                           36 bytes
   (encrypted in place, then followed by metadata)
```

单条记录（48 字节，小端）：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `idx` | 4 | 块索引 |
| `nonce` | 12 | ChaCha20 随机 nonce |
| `tag` | 32 | HMAC-SHA256 认证标签 |

fixed 尾部（36 字节，小端）：

| 字段 | 长度 | 说明 |
| --- | --- | --- |
| `magic` | 8 | `"PHENC04\0"`，标识格式与版本 |
| `blockSize` | 4 | 固定 1 MiB |
| `totalBlocks` | 4 | 文件总块数 |
| `encCount` | 4 | 已加密块数 |
| `salt` | 16 | PBKDF2 盐 |

### 解密流程

1. 从文件末尾读取 36 字节 fixed，校验 `magic`
2. 由 `fileSize - 36 - encCount × 48` 反推 `originalSize`
3. 读取全部记录，用密码和盐重新派生密钥
4. 逐块校验 HMAC 标签，通过后用相同 nonce 异或还原
5. 将文件截断回 `originalSize`

**体积开销**：`encCount × 48 + 36` 字节。例如 3 MiB 文件按 25% 加密（`totalBlocks = 3`，`encCount = 1`）只增加 84 字节。

**未选中的块保持明文**——这是比例加密的固有特性（见下节）。

## 安全模型与限制

请务必了解以下几点，它们决定了本工具适合什么场景：

- **比例加密 ≠ 全文加密**：`ratio < 100` 时，未被选中的块仍是完整明文。文件的可读内容、可检索文本会部分保留。需要严格机密性时请用 100% 或专用加密工具。
- **原地操作、无备份**：加密/解密直接改写原文件，中途失败（断电、文件被占用、磁盘满）可能留下部分处理过的文件；解密会截断尾部。重要数据请先备份。
- **随机性来源**：salt 与 nonce 由 `std::mt19937_64` 生成，种子取自 `std::random_device` 和高精度时钟。它**不是密码学安全的随机数生成器**，nonce/salt 在严格意义上属于伪随机。
- **自实现密码学原语**：SHA-256、HMAC、PBKDF2、ChaCha20 均为项目内手写实现，仅用 `-O2` 优化，未使用 Windows CNG/OpenSSL，也**未经过第三方密码学审计**。请勿用于高价值或合规场景。
- **无密钥管理**：密码只存在于内存，不落盘；没有密钥文件、找回或恢复机制，忘记密码即无法恢复。
- **不隐藏元信息**：文件名、路径、文件大小（仅增加几十字节）均未改动，加密特征（`PHENC04` 尾部）可被识别。
- **解密是破坏性的**：解密成功即删除尾部元数据并还原明文，无法再次「撤销」为密文（需重新加密）。

## 项目结构

```
WuSi_Encrypter/
├── main.cpp                 单文件源码：密码学原语 + 文件格式 + GUI + CLI
├── resource.rc              资源脚本（仅引用图标）
├── app.ico                  应用图标
├── resource.o               由 resource.rc 编译出的资源对象（构建产物）
├── build.bat                MinGW-w64 全静态构建脚本
├── WuSi_FileEncryptor.exe   预编译程序（与 build.bat 输出同一二进制）
└── README.md
```

`main.cpp` 内部按顺序分为四部分：

1. 密码学原语：`SHA256` / `HMAC_SHA256` / `pbkdf2` / `ChaCha20` / `randomBytes`
2. 文件格式：`encryptFileW` / `decryptFileW`（原地分块加解密）
3. 图形界面：DPI 感知、自绘按钮、拖放、布局与日志
4. 程序入口：`wWinMain` 分流 GUI / CLI

## 构建说明

- 编译器：MinGW-w64 g++ 8.1.0（x86_64-win32-seh），支持 C++17
- 关键链接选项：
  - `-municode -mwindows`：Unicode 入口、GUI 子系统（命令行模式通过 `AttachConsole`/`AllocConsole` 输出）
  - `-static -static-libgcc -static-libstdc++`：静态链接所有运行时，产物不依赖 MinGW DLL
  - `-s`：剥离符号
- 依赖库：`comctl32 shell32 ole32 uuid gdi32`（`dwmapi` 仅在运行时动态加载，用于 Win11 圆角）

产物仅导入系统 DLL：`KERNEL32 / USER32 / GDI32 / COMCTL32 / COMDLG32 / SHELL32 / msvcrt`。

> 注意：`resource.o` 为已生成的中间产物，重新构建时会被覆盖。

## 兼容性

- 目标平台：**Windows 10 1703+ / Windows 11**（Per-Monitor V2 DPI 与 Win11 窗口圆角等特性在此版本起完整生效）
- 更低版本会自动回退到 Per-Monitor / System DPI 感知，功能仍可用
- 构建产物为 **64 位** 可执行文件

## 已知问题

- 内置帮助里的示例程序名为 `file_crypt.exe`，与实际 exe 名不一致（仅为文案，不影响功能）。
- `-h` 需要跟在子命令之后才能生效（如 `WuSi_Encrypter.exe enc -h`）；直接以 `-h` 作为首个参数会被当成未知命令并返回退出码 1。
- 命令行模式会把结果直接写到控制台（无控制台时自动新建窗口），通过 `>` 重定向到文件通常拿不到输出内容。
- 程序为 GUI 子系统，在 `cmd` 中调用时 `cmd` 不会等待其结束，脚本中建议用 `start /wait` 或 PowerShell 的 `Start-Process -Wait` 获取真实退出码。
- 界面为固定尺寸窗口，不支持缩放；仅适配浅色主题。

## 免责声明

本项目按「现状」提供，用于学习、个人文件遮护与离线工具场景。因密码遗忘、文件损坏、误操作或安全模型不匹配造成的任何数据丢失或泄露，作者不承担责任。使用前请备份数据，并自行评估其是否满足你的安全需求与当地法规。
