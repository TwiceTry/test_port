# 端口开放测试工具 (TCP/UDP, 防风控版)

针对**移动家庭宽带**端口屏蔽场景设计的 C/S 测试工具。通过在家庭主机运行服务端、在
一台公网可达机器(如 Windows 笔记本 / VPS)运行客户端, 探测哪些端口能被公网访问,
从而识别运营商屏蔽的端口。

全部为 **Python 脚本**, 跨平台一致 (Windows / Linux / macOS 只需装好 Python)。

## 文件清单

| 文件 | 作用 |
|------|------|
| `port_probe_server.py` | **服务端**, 跑在家庭宽带主机, 被动监听并响应带 token 的探测包 |
| `port_probe_client.py` | **客户端**, 跑在公网侧机器, 温和地向家庭主机发起探测, 支持 CSV 导出 |
| `run_port_probe.py` | **一键辅助**, 自动探测本机公网 IP 并生成两端可直接运行的命令 |
| `README.md` | 本说明 |

## 为什么需要 C/S 结构

家庭宽带通常拿不到公网 IPv4 (CGNAT), 或即使有公网 IP 也被运营商屏蔽入站端口。
要从"外部"判断端口是否开放, 必须在**公网侧**发起连接、在家庭侧监听响应。因此天然是 C/S 架构:
- **Server**: 跑在家庭宽带主机上, 被动监听并响应带 token 的探测包。
- **Client**: 跑在公网机器上, 温和地向家庭主机发起探测。

## 防风控设计 (关键)

运营商对"大批量/规律性"端口扫描会限速甚至临时封 IP。本工具从多个维度规避:

| 措施 | 默认 | 说明 |
|------|------|------|
| 端口数上限 | 20 | `--max-ports`, 防止误扫全段 |
| 探测速率 | 2/s | `--rate`, 全局速率限制 |
| 随机延迟 | 0.3~1.2s | `--min-delay/--max-delay`, 打散流量节律 |
| 顺序随机 | 开 | 端口探测顺序打乱 |
| 并发数 | 1 | `--concurrency`, 避免报文突发 |
| UDP 行为 | 单发单等 | 超时即判屏蔽, 不重发狂轰 |
| token 校验 | 开 | 只响应本方案包, 不对第三方主机扫描 |

**不要**把 `--ports` 改成 `1-65535` 或把 `--rate` 调很高, 那会直接触发风控。

## 快速开始

### 方式一: 一键辅助脚本 (推荐)

在家庭宽带主机上运行, 它会自动探测本机公网 IP 并打印出两端命令:

```bash
python run_port_probe.py --token SECRET2026 --ports 22,80,443,10000,10001
```

输出包含:
- 本机公网 IPv4 / IPv6
- 服务端命令 (复制到家庭主机执行)
- 客户端命令 (复制到公网侧机器执行, 已自动填好 `--host`)

可选参数:
- `--auto`  : 本机直接后台启动服务端 (调试用)
- `--csv`   : 透传到客户端命令, 结果导出 CSV
- `--token` : 自定义令牌
- `--ports` : 自定义端口

### 方式二: 手动分别运行

**1. 家庭主机 (Server)** —— Linux 示例:

```bash
# 放行防火墙
sudo ufw allow 10000:10004/tcp
sudo ufw allow 10000:10004/udp
# 若路由器做了 NAT, 需把端口做转发到本机

python port_probe_server.py --ports 10000,10001,10002,10003,10004 --token SECRET2026
```

Windows 服务端防火墙放行 (PowerShell 管理员):
```powershell
netsh advfirewall firewall add rule name=probe_tcp dir=in action=allow protocol=TCP localport=10000,10001,10002,10003,10004
netsh advfirewall firewall add rule name=probe_udp dir=in action=allow protocol=UDP localport=10000,10001,10002,10003,10004
```

**2. 公网侧机器 (Client)** —— 替换成家庭主机公网 IP:

```bash
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 \
    --ports 10000,10001,10002,10003,10004,22,80,443,3389,8080
```

端口支持**范围写法** (`--ports`/`--tcp-ports`/`--udp-ports` 通用):

```bash
# 范围: 展开为 21114,21115,21116,21117,21118,21119
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 --ports 21114-21119

# 混合: 单个 + 逗号 + 范围
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 --ports 22,80,21114-21119,30000

# TCP/UDP 分别指定范围
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 \
    --tcp-ports 21114-21119 --udp-ports 21114-21119
```

范围会自动去重、纠正方向 (如 `21119-21114` 等价于 `21114-21119`), 超出 1-65535 会报错提示。
注意: 范围展开后**端口总数仍计入 `--max-ports` 上限**, 不要写 `1-65535` 这类大段以触发风控。

### 3. IPv6 目标

家庭主机若已有公网 IPv6, 客户端加 `--family ipv6`:

```bash
python port_probe_client.py --host 2409:8a44:xxxx::xxxx --family ipv6 --token SECRET2026
```

### 4. 使用预设端口组 (--preset)

不想每次手敲端口, 可用内置预设 (端口数均控制在防风控上限内):

| 预设 | 覆盖端口 | 用途 |
|------|----------|------|
| `mobile`   | TCP 25,80,135,139,443,445,465,995,3389,8080,8443; UDP 53,137,138,500,4500,10000,10001 | 移动宽带典型被屏蔽/需验证端口 (邮件/文件共享/常见服务) |
| `common`   | TCP 22,80,443,3389,8080,8443,10000-10002; UDP 53,123,500,4500,10000,10001 | 常见自建服务端口, 验证基础连通 |
| `high`     | TCP 10000-10004,20000,30000,40000; UDP 10000-10004 | 仅测高位自定义端口 (家庭 NAS/反代常用) |
| `windows`  | TCP 135,137,138,139,445,3389,5985,5986; UDP 137,138,445 | Windows 文件共享/远程类 (常被运营商封) |

```bash
# 直接测移动宽带典型端口
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 --preset mobile

# 预设基础上追加自己的端口
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 --preset common \
    --tcp-ports 22,80,443,3389,8080,8443,10000,10001,10002,9000
```

注意: 预设展开后仍受 `--rate`/`--min-delay`/`--max-delay` 限速保护; 若手动追加端口超过
`--max-ports`(默认 20) 会提示缩减, 但预设本身因是精选集合会自动放行。

## 导出 CSV

客户端加 `--csv` 即可把结果导出为结构化 CSV (UTF-8 BOM, Excel 直接可打开):

```bash
python port_probe_client.py --host 120.213.179.31 --token SECRET2026 \
    --ports 22,80,443,10000 --csv result.csv
```

CSV 字段: `proto, port, open, latency_ms, note, target, family`

## 输出解读

- `OPEN` + 延迟: 端口公网可达, 未被屏蔽。
- `closed(refused)`: 端口通但无服务监听 (TCP RST)。
- `filtered/timeout`: 超时无响应, **通常表示运营商/防火墙屏蔽或丢弃** (UDP 尤为常见)。

## 常用端口参考 (移动宽带典型屏蔽)

可针对性测试以下端口, 观察哪些被屏蔽:

- 邮件/Windows 文件共享类常被屏蔽: 25, 135, 137, 138, 139, 445
- 部分低位端口: 1-1023 区间很多被封
- 常见自建服务端口: 22, 80, 443, 3389, 8080, 8443, 以及高位自定义端口(如 10000+ 通常开放)

## Windows 使用注意

- 建议在 CMD / PowerShell 里运行, 例如:
  ```bat
  cd /d D:\path\to\test_port
  python port_probe_client.py --host 120.213.179.31 --token SECRET2026 --ports 10000,10001
  ```
  (`python` 不行就试 `py`)
- 脚本所有输出均 `flush`, 不会因缓冲被吞; 双击运行时结束前会等待"按回车", 不会一闪而过。
- 若运行后**完全无输出就退出**, 多半是缺 `--host` 或 IP 不通, 用重定向看错误:
  ```bat
  python port_probe_client.py --host x.x.x.x ... > out.txt 2>&1
  ```
  把 `out.txt` 内容发出来即可定位。

## 调参建议

- 想更隐蔽: 调低 `--rate 1`、加大 `--max-delay 2.0`、缩小端口列表。
- 想更快: 适度调高 `--rate`(如 4), 但**不要**提高并发或扫全段。
- 测试完记得关闭服务端进程, 减少暴露面。
