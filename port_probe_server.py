#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
port_probe_server.py — 端口开放测试 服务端
=============================================

用途:
    在家庭宽带主机(被测试端)上运行, 监听一组 TCP/UDP 端口。
    当客户端(另一台机器, 比如你的云服务器/VPS) 向这些端口发起连接/发包时,
    本服务做出响应, 从而让客户端判断: 该端口是否能被公网访问 (即运营商是否屏蔽)。

设计要点 (配合防风控):
    - 服务端只做"被动响应", 不主动发包, 不会触发任何扫描风控。
    - 内置一个轻量 magic 校验, 只响应带正确 token 的探测包, 忽略杂物流量。
    - 支持只监听少量端口(默认 5 个), 减少暴露面。
    - UDP 用"收到 magic 则回显"的方式判定开放。

使用:
    python3 port_probe_server.py --ports 10000,10001,10002,10003,10004 --token SECRET2026
    # 默认监听 0.0.0.0 (IPv4) 与 :: (IPv6), 可用 --host 限定

注意:
    - 若家庭路由做了 NAT, 需要在路由器上做端口转发到本机。
    - 若使用 IPv6, 关闭防火墙对应端口或放行: ufw allow 10000:10004/tcp 等。
"""

import argparse
import socket
import sys
import threading
import time

MAGIC_PREFIX = b"PROBE-"  # 探测包必须以该前缀开头, 后接 token


def build_expect(token: str) -> bytes:
    return MAGIC_PREFIX + token.encode()


def handle_tcp(conn: socket.socket, addr, expect: bytes, token: str):
    try:
        conn.settimeout(5)
        data = conn.recv(64)
        if data == expect:
            conn.sendall(b"OK:" + token.encode())
            print(f"[TCP] {addr[0]}:{addr[1]} -> OPEN (port {conn.getsockname()[1]})")
        else:
            print(f"[TCP] {addr[0]}:{addr[1]} -> bad token, ignored")
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[TCP] err {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def tcp_listener(port: int, expect: bytes, token: str):
    s = socket.socket(socket.AF_INET6 if False else socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", port))
    s.listen(16)
    print(f"[TCP] listening on :{port}")
    while True:
        try:
            conn, addr = s.accept()
        except KeyboardInterrupt:
            break
        t = threading.Thread(target=handle_tcp, args=(conn, addr, expect, token), daemon=True)
        t.start()


def udp_listener(port: int, expect: bytes, token: str):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", port))
    print(f"[UDP] listening on :{port}")
    while True:
        try:
            data, addr = s.recvfrom(128)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[UDP] err {e}")
            continue
        if data == expect:
            s.sendto(b"OK:" + token.encode(), addr)
            print(f"[UDP] {addr[0]}:{addr[1]} -> OPEN (port {port})")
        # 非 magic 包忽略, 不响应, 避免被利用做反射放大


def main():
    ap = argparse.ArgumentParser(description="端口开放测试服务端")
    ap.add_argument("--ports", default="10000,10001,10002,10003,10004",
                    help="逗号分隔的端口列表 (同时用于 TCP 和 UDP)")
    ap.add_argument("--token", default="SECRET2026", help="探测令牌(与服务端一致)")
    ap.add_argument("--udp-ports", default=None,
                    help="仅 UDP 的额外端口, 逗号分隔; 默认复用 --ports")
    ap.add_argument("--tcp-ports", default=None,
                    help="仅 TCP 的额外端口, 逗号分隔; 默认复用 --ports")
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    udp_ports = [int(p) for p in args.udp_ports.split(",") if p.strip()] if args.udp_ports else ports
    tcp_ports = [int(p) for p in args.tcp_ports.split(",") if p.strip()] if args.tcp_ports else ports

    expect = build_expect(args.token)
    threads = []
    for p in set(tcp_ports):
        t = threading.Thread(target=tcp_listener, args=(p, expect, args.token), daemon=True)
        t.start(); threads.append(t)
    for p in set(udp_ports):
        t = threading.Thread(target=udp_listener, args=(p, expect, args.token), daemon=True)
        t.start(); threads.append(t)

    print(f"服务端已启动, token={args.token}, TCP端口={sorted(set(tcp_ports))}, UDP端口={sorted(set(udp_ports))}")
    print("按 Ctrl+C 退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在退出...")
        sys.exit(0)


if __name__ == "__main__":
    main()
