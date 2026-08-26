#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
port_probe_client.py — 端口开放测试 客户端 (温和扫描版)
=========================================================

用途:
    从一台"公网可达"的机器(如云服务器/Windows 笔记本)向家庭宽带主机发起探测,
    判断各端口是否能被公网访问 (从而识别运营商屏蔽了哪些端口)。

防风控设计 (非常重要):
    1. 默认只测"代表性端口", 绝不扫全段 (不要改成 1-65535 !)。
    2. 端口顺序随机打乱, 避免规律性流量被识别为扫描。
    3. 每个探测之间随机延迟 (--min-delay / --max-delay), 默认 0.3~1.2 秒。
    4. 全局速率限制 (--rate), 默认每秒最多 ~2 个探测, 远低于风控阈值。
    5. 串行+极低并发 (--concurrency 默认 1), 避免瞬时报文突发。
    6. UDP 用"发 magic -> 等响应"判定, 超时即视为屏蔽/丢包, 不重发狂轰。
    7. 单 IP 单次运行探测端口数默认上限 20, 防止误用触发风控。
    8. 所有流量带 token, 只与本方案服务端配合, 不对第三方主机扫描。

Windows 使用注意:
    - 建议在 CMD 或 PowerShell 里运行:  python port_probe_client.py --host x.x.x.x ...
    - 若直接双击运行, 本脚本会在结束前等待"按回车", 不会一闪而过。
    - 所有输出均 flush, 不会因缓冲而吞掉。

使用:
    python port_probe_client.py --host <家庭宽带公网IP> --token SECRET2026 \
        --ports 10000,10001,10002,10003,10004,22,80,443,3389,8080

IPv6 目标:
    python port_probe_client.py --host 2409:8a44:xxxx::xxxx --family ipv6 ...
"""

import argparse
import csv
import queue
import random
import socket
import sys
import threading
import time

MAGIC_PREFIX = b"PROBE-"
TCP_TIMEOUT = 3.0
UDP_TIMEOUT = 3.0


def build_probe(token: str) -> bytes:
    return MAGIC_PREFIX + token.encode()


def log(msg):
    """带 flush 的打印, 避免 Windows 下输出被缓冲吞掉."""
    print(msg, flush=True)


def probe_tcp(host, port, family, token, timeout):
    pkt = build_probe(token)
    af = socket.AF_INET6 if family == "ipv6" else socket.AF_INET
    s = socket.socket(af, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.time()
    try:
        s.connect((host, port))
        s.sendall(pkt)
        resp = s.recv(64)
        if resp.startswith(b"OK:"):
            return True, round((time.time() - start) * 1000), "open"
    except socket.timeout:
        return False, None, "filtered/timeout"
    except (ConnectionRefusedError, ConnectionResetError):
        return False, None, "closed(refused)"
    except OSError as e:
        return False, None, f"error({e})"
    finally:
        s.close()
    return False, None, "no-response"


def probe_udp(host, port, family, token, timeout):
    pkt = build_probe(token)
    af = socket.AF_INET6 if family == "ipv6" else socket.AF_INET
    s = socket.socket(af, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    start = time.time()
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(128)
        if data.startswith(b"OK:"):
            return True, round((time.time() - start) * 1000), "open"
    except socket.timeout:
        return False, None, "filtered/timeout(no-response)"
    except OSError as e:
        return False, None, f"error({e})"
    finally:
        s.close()
    return False, None, "no-response"


def worker(task_queue, results, args, rate_lock, rate_interval, stop_flag):
    """单线程串行消费队列, 受全局速率锁限制."""
    while not stop_flag.is_set():
        try:
            item = task_queue.get_nowait()
        except queue.Empty:
            break
        except Exception:
            break
        proto, port = item
        try:
            if proto == "tcp":
                ok, ms, note = probe_tcp(args.host, port, args.family, args.token, TCP_TIMEOUT)
            else:
                ok, ms, note = probe_udp(args.host, port, args.family, args.token, UDP_TIMEOUT)
        except Exception as e:
            ok, ms, note = False, None, f"error({e})"

        with rate_lock:
            results.append((proto, port, ok, ms, note))
            mark = "OPEN " if ok else "---- "
            timestr = f"{ms}ms" if ms is not None else "  -  "
            log(f"  [{mark}] {proto.upper():3} {port:6}  {timestr:>6}  {note}")

        time.sleep(rate_interval)
        time.sleep(random.uniform(args.min_delay, args.max_delay))


def main():
    ap = argparse.ArgumentParser(description="端口开放测试客户端 (温和版)")
    ap.add_argument("--host", required=True, help="目标公网 IP 或域名")
    ap.add_argument("--token", default="SECRET2026", help="与服务端一致的令牌")
    ap.add_argument("--ports", default="10000,10001,10002,10003,10004",
                    help="逗号分隔端口; tcp/udp 通用")
    ap.add_argument("--tcp-ports", default=None, help="仅测 TCP 的端口(覆盖 --ports 的 tcp 部分)")
    ap.add_argument("--udp-ports", default=None, help="仅测 UDP 的端口(覆盖 --ports 的 udp 部分)")
    ap.add_argument("--family", default="ipv4", choices=["ipv4", "ipv6"],
                    help="目标地址族")
    ap.add_argument("--rate", type=float, default=2.0,
                    help="每秒最大探测数 (默认 2.0, 越低越安全)")
    ap.add_argument("--min-delay", type=float, default=0.3,
                    help="每个探测后最小随机延迟(秒)")
    ap.add_argument("--max-delay", type=float, default=1.2,
                    help="每个探测后最大随机延迟(秒)")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="并发 worker 数 (默认 1, 强烈建议保持 1)")
    ap.add_argument("--max-ports", type=int, default=20,
                    help="单次运行最大端口总数, 防止误用触发风控")
    ap.add_argument("--csv", default=None,
                    help="将结果导出为 CSV 文件路径, 如 ./result.csv")
    args = ap.parse_args()

    if args.concurrency > 1:
        log("[警告] 并发>1 会增加突发流量, 不建议在运营商网络中提高。已按你设置运行。")

    # 构造任务
    tasks = []
    tcp_ports = [int(p) for p in (args.tcp_ports or args.ports).split(",") if p.strip()]
    udp_ports = [int(p) for p in (args.udp_ports or args.ports).split(",") if p.strip()]
    for p in tcp_ports:
        tasks.append(("tcp", p))
    for p in udp_ports:
        tasks.append(("udp", p))

    # 随机打乱顺序 (防风控)
    random.shuffle(tasks)

    if len(tasks) > args.max_ports:
        log(f"[错误] 端口总数 {len(tasks)} 超过安全上限 {args.max_ports}。"
            f"请缩减端口或显式调高 --max-ports (不推荐)。")
        return

    rate_interval = 1.0 / max(args.rate, 0.1)
    total_est = len(tasks) * (rate_interval + (args.min_delay + args.max_delay) / 2)
    log(f"目标: {args.host} ({args.family})  token={args.token}")
    log(f"待探测: {len(tasks)} 个 (TCP={len(tcp_ports)}, UDP={len(udp_ports)})")
    log(f"速率: ~{args.rate}/s, 延迟 {args.min_delay}-{args.max_delay}s, 并发 {args.concurrency}")
    log(f"预计耗时: ~{total_est:.0f}s")
    log("-" * 50)

    task_queue = queue.Queue()
    for t in tasks:
        task_queue.put(t)
    results = []
    rate_lock = threading.Lock()
    stop_flag = threading.Event()

    threads = []
    for _ in range(max(1, args.concurrency)):
        th = threading.Thread(
            target=worker,
            args=(task_queue, results, args, rate_lock, rate_interval, stop_flag),
            daemon=True,
        )
        th.start(); threads.append(th)

    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        stop_flag.set()
        log("\n[中断] 已停止。")

    # 汇总
    opens = [r for r in results if r[2]]
    log("-" * 50)
    log(f"结果: 共 {len(results)} 探测, 开放 {len(opens)}, 被屏蔽/不可达 {len(results)-len(opens)}")
    if opens:
        log("开放端口:")
        for proto, port, ok, ms, note in opens:
            log(f"  {proto.upper():3} {port:6}  ({ms}ms)")
    log("提示: 'filtered/timeout' 通常表示运营商屏蔽或防火墙丢弃。")

    # CSV 导出
    if args.csv:
        try:
            with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["proto", "port", "open", "latency_ms", "note", "target", "family"])
                for proto, port, ok, ms, note in results:
                    w.writerow([proto, port, "yes" if ok else "no",
                                ms if ms is not None else "", note, args.host, args.family])
            log(f"结果已导出: {args.csv}")
        except Exception as e:
            log(f"[警告] CSV 导出失败: {e}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        log(f"[致命错误] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Windows 双击运行时, 防止窗口一闪而过
        if sys.platform.startswith("win"):
            try:
                input("\n按回车键退出...")
            except Exception:
                pass
