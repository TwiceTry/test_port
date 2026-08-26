#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_port_probe.py — 端口开放测试 一键辅助脚本 (跨平台 Python 版)
================================================================

统一替代 run_port_probe.sh / run_port_probe.bat, 在任何装了 Python 的
系统(Windows / Linux / macOS)上行为一致。

功能:
    1. 自动探测本机公网 IPv4 / IPv6 地址
    2. 生成"服务端"(家庭宽带主机) 与 "客户端"(公网侧) 两段可直接运行命令
    3. 可选 --auto: 本机直接后台拉起服务端, 并打印客户端命令

用法:
    python run_port_probe.py
    python run_port_probe.py --token MYSEC --ports 22,80,443,10000,10001
    python run_port_probe.py --auto            # 本机直接启动服务端
    python run_port_probe.py --csv result.csv  # 透传到客户端命令

注意:
    本脚本只做"探测IP + 生成命令", 真正的探测由 port_probe_client.py 完成。
    防火墙/NAT 端口转发仍需按提示手动处理。
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def log(msg=""):
    print(msg, flush=True)


def detect_public_ip():
    """探测公网 IPv4 / IPv6, 失败时返回 None."""
    def fetch(url, v6=False):
        # 通过 curl 探测 (优先), 失败则用 urllib 兜底
        try:
            if v6:
                out = subprocess.run(
                    ["curl", "-6", "-s", "--max-time", "8", url],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()
            else:
                out = subprocess.run(
                    ["curl", "-4", "-s", "--max-time", "8", url],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()
            if out:
                return out
        except Exception:
            pass
        # urllib 兜底
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "probe"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.read().decode().strip()
        except Exception:
            return None

    ipv4 = fetch("https://ip.sb") or fetch("https://icanhazip.com")
    ipv6 = fetch("https://ip.sb", v6=True)
    return ipv4, ipv6


def main():
    ap = argparse.ArgumentParser(description="端口开放测试 一键辅助 (跨平台)")
    ap.add_argument("--token", default="SECRET2026", help="与服务端一致的令牌")
    ap.add_argument("--ports", default="10000,10001,10002,10003,10004",
                    help="逗号分隔端口")
    ap.add_argument("--auto", action="store_true",
                    help="本机直接后台启动服务端")
    ap.add_argument("--csv", default=None, help="客户端结果导出 CSV 路径")
    args = ap.parse_args()

    server_py = os.path.join(HERE, "port_probe_server.py")
    client_py = os.path.join(HERE, "port_probe_client.py")

    log("==================================================")
    log(" 端口开放测试 · 一键辅助 (跨平台 Python)")
    log("==================================================")

    log("[1/3] 探测公网地址...")
    ipv4, ipv6 = detect_public_ip()
    log(f"      公网 IPv4 : {ipv4 or '获取失败'}")
    log(f"      公网 IPv6 : {ipv6 or '无/获取失败'}")

    # 服务端命令
    server_cmd = f'python "{server_py}" --ports {args.ports} --token {args.token}'

    # 客户端命令
    client_base = f'python "{client_py}" --token {args.token} --ports {args.ports}'
    csv_suffix = f" --csv {args.csv}" if args.csv else ""
    client_v4 = f"{client_base} --host {ipv4}{csv_suffix}" if ipv4 else None
    client_v6 = (f"{client_base} --host {ipv6} --family ipv6{csv_suffix}"
                 if ipv6 else None)

    log("")
    log("[2/3] 在家庭宽带主机运行 (服务端):")
    log("--------------------------------------------------")
    log(f"  {server_cmd}")
    log("  # 若路由器 NAT, 需把端口转发到本机, 并放行防火墙:")
    log(f"  #   Linux : sudo ufw allow {args.ports}/tcp && sudo ufw allow {args.ports}/udp")
    log(f"  #   Win   : netsh advfirewall firewall add rule name=probe_tcp dir=in action=allow protocol=TCP localport={args.ports}")
    log("")
    log("[3/3] 在公网侧机器运行 (客户端):")
    log("--------------------------------------------------")
    if client_v4:
        log("  # IPv4 目标:")
        log(f"  {client_v4}")
    if client_v6:
        log("  # IPv6 目标:")
        log(f"  {client_v6}")
    log("==================================================")

    if args.auto:
        log("")
        log("[自动模式] 本机后台启动服务端...")
        log_file = os.path.join(HERE, "server_auto.log")
        try:
            if os.name == "nt":
                subprocess.Popen(
                    ["python", server_py, "--ports", args.ports, "--token", args.token],
                    stdout=open(log_file, "w"), stderr=subprocess.STDOUT,
                    creationflags=0x08000000,  # CREATE_NO_WINDOW
                )
            else:
                subprocess.Popen(
                    ["python3", server_py, "--ports", args.ports, "--token", args.token],
                    stdout=open(log_file, "w"), stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            log(f"服务端已在后台启动, 日志: {log_file}")
            log("探测完成后结束该 python 进程即可。")
            log("客户端命令已在上文 [3/3], 复制到公网侧机器执行。")
        except Exception as e:
            log(f"[警告] 自动启动服务端失败: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n已取消。")
    except Exception as e:
        log(f"[致命错误] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if sys.platform.startswith("win"):
            try:
                input("\n按回车键退出...")
            except Exception:
                pass
