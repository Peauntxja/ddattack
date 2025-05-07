# DDoS 攻击工具

这是一个用Python实现的DDoS攻击工具，**仅用于教育目的**。该工具提供HTTP洪水、TCP SYN洪水、UDP洪水、SlowLoris攻击等多种攻击方法。

## 免责声明

**这个工具仅用于教育目的！**

使用此工具对未经许可的网络或服务器进行攻击是违法的，可能导致严重的法律后果。作者不对任何滥用此工具造成的损害负责。请负责任地使用，并确保在使用前获得明确授权。

## 功能特点

- 支持多种攻击类型：
  - HTTP洪水攻击：向目标发送大量HTTP GET/POST请求
  - TCP SYN洪水攻击：向目标发送大量TCP SYN包
  - UDP洪水攻击：向目标发送大量UDP数据包
  - SlowLoris攻击：保持大量半开HTTP连接，消耗服务器资源
  - Scapy TCP SYN攻击（高级）：使用Scapy库实现更强大的SYN攻击，支持IP伪造
- 增强功能：
  - 目标可达性检测：在攻击前检查目标是否可达
  - 自动保存攻击结果：将攻击详情保存为JSON文件以供分析
  - HTTP POST请求支持：除GET请求外，HTTP攻击还支持POST请求
- 多线程支持：提高攻击效率
- 域名解析：支持输入域名或IP地址（支持完整URL格式）
- 命令行参数：支持通过命令行参数控制攻击
- 交互式菜单：用户友好的交互式操作界面
- 攻击统计：显示攻击过程中的统计信息

## 安装

1. 克隆此仓库：
```
git clone <repository_url>
cd ddAttack
```

2. 安装依赖：
```
# 使用Python 3
python3 -m pip install -r requirements.txt

# 如果在macOS上使用pip遇到问题
python3 -m pip install -r requirements.txt
```

## 权限要求

### Scapy SYN 攻击权限

使用Scapy进行SYN洪水攻击需要**管理员/root权限**，因为它需要创建原始套接字发送数据包。

- **Linux/macOS**：使用`sudo`运行脚本
  ```
  sudo python3 ddos_attack.py
  ```
  
- **macOS特别说明**：在macOS上，未使用root权限运行时可能会遇到 `Permission denied: could not open /dev/bpf0` 错误。这是因为Scapy需要访问Berkeley Packet Filter (BPF)设备。

- **Windows**：以管理员身份运行命令提示符

### 其他攻击类型

HTTP、TCP、UDP和SlowLoris攻击不需要管理员/root权限，可以直接运行：
```
python3 ddos_attack.py
```

## 使用方法

### 交互式菜单

直接运行脚本，将显示交互式菜单：
```
python3 ddos_attack.py
```

### 命令行参数

也可以使用命令行参数启动攻击：
```
python3 ddos_attack.py -t TARGET -p PORT -a ATTACK_TYPE -d DURATION -T THREADS
```

参数说明：
- `-t, --target`：目标IP地址或域名（支持完整URL，如https://example.com）
- `-p, --port`：目标端口
- `-a, --attack`：攻击类型（http, tcp, udp, syn, slowloris）
- `-d, --duration`：攻击持续时间（秒）
- `-T, --threads`：线程数（默认：10）
- `-s, --size`：数据包/POST数据大小（默认：1024）
- `-u, --user-agent`：HTTP请求的User-Agent（默认：Mozilla/5.0）
- `--scapy`：使用Scapy进行高级SYN攻击（仅适用于syn攻击类型）
- `--post`：使用POST请求而非GET请求（仅适用于http攻击类型）
- `--socket-count`：SlowLoris攻击的每线程连接数（默认：150）
- `--check`：在攻击前检查目标可达性
- `--save`：自动保存攻击结果

示例：
```
# HTTP GET洪水攻击
python3 ddos_attack.py -t example.com -p 80 -a http -d 30 -T 20

# HTTP POST洪水攻击
python3 ddos_attack.py -t example.com -p 80 -a http -d 30 -T 20 --post -s 4096

# 也支持完整URL
python3 ddos_attack.py -t https://example.com -p 80 -a http -d 30 -T 20

# TCP SYN洪水攻击（带目标可达性检查）
python3 ddos_attack.py -t 192.168.1.1 -p 443 -a tcp -d 30 -T 50 --check

# UDP洪水攻击
python3 ddos_attack.py -t 192.168.1.1 -p 53 -a udp -d 30 -T 100 -s 2048

# SlowLoris攻击
python3 ddos_attack.py -t example.com -p 80 -a slowloris -d 60 -T 5 --socket-count 200

# 使用Scapy的高级SYN攻击（需要root权限）并保存结果
sudo python3 ddos_attack.py -t 192.168.1.1 -p 80 -a syn -d 30 -T 50 --scapy --save
```

## 攻击类型详解

### HTTP洪水攻击
向Web服务器发送大量HTTP请求，消耗其处理资源。支持GET和POST两种请求方式。

- **优点**：针对Web服务器效果好，容易绕过简单防火墙
- **缺点**：速度相对较慢，容易被WAF检测

### TCP SYN洪水攻击
利用TCP三次握手机制，发送大量SYN包但不完成握手，消耗服务器连接资源。

- **优点**：适用于任何TCP服务，不仅限于Web服务器
- **缺点**：使用真实IP地址，容易被追踪

### UDP洪水攻击
发送大量UDP数据包到目标服务器，适用于DNS、VOIP等UDP服务。

- **优点**：速度快，资源消耗小
- **缺点**：容易被防火墙过滤

### SlowLoris攻击
一种低带宽消耗的攻击方式，通过保持大量半开HTTP连接，耗尽服务器的连接池。

- **优点**：资源消耗小，难以在网络层面检测
- **缺点**：仅适用于某些Web服务器，新版服务器可能有防护

### Scapy TCP SYN攻击（高级）
使用Scapy库实现更高级的SYN洪水攻击，支持IP伪造，更难被追踪。

- **优点**：可伪造源IP地址，更难被追踪，更高效
- **缺点**：需要root/管理员权限运行

## 攻击结果保存

工具支持将攻击结果保存为JSON格式文件，包含以下信息：
- 攻击时间戳
- 攻击类型
- 目标信息
- 攻击持续时间
- 发送的数据包数量
- 每秒发送的数据包数等统计信息

## Scapy扩展功能

该工具包含一个使用Scapy库实现的高级TCP SYN洪水攻击模块（ddos_scapy_ext.py）。该模块提供以下增强功能：

- IP伪造：生成随机源IP地址，使攻击更难被追踪
- 自定义TCP包头：完全控制TCP包的各种参数
- 更高效的数据包发送机制

要使用Scapy扩展功能，需要安装Scapy库：
```
python3 -m pip install scapy
```

**重要提示**：Scapy需要root/管理员权限才能正常工作，这是因为它需要创建原始套接字（raw socket）来发送自定义数据包。如果没有足够的权限，程序会提示您并提供使用普通TCP SYN攻击的选项。

## 故障排除

1. **Scapy权限问题**：
   - 错误信息：`Permission denied: could not open /dev/bpf0`（macOS）或类似错误
   - 解决方案：使用`sudo python3 ddos_attack.py`运行脚本

2. **域名解析失败**：
   - 错误信息：`无法解析域名`
   - 解决方案：确保输入了有效的域名或IP地址，检查网络连接
   - 如果您输入的是完整URL（如`https://example.com`），工具会自动提取域名部分

3. **Python版本问题**：
   - 错误信息：与Python版本相关的错误
   - 解决方案：确保使用Python 3.6+，并使用`python3`命令

4. **目标不可达**：
   - 错误信息：`目标不可达`
   - 解决方案：确认目标服务器是否在线，检查防火墙设置

## 注意事项

- 确保在使用此工具前获得明确授权
- 避免攻击公共服务或关键基础设施
- 仅在受控环境中用于测试和学习目的
- 对使用此工具造成的任何后果自行负责

## 最低系统要求

- Python 3.6+
- 网络连接
- 可选：Scapy库（用于高级SYN攻击）
- 可选：root/管理员权限（用于Scapy SYN攻击） 

## 许可证

本项目采用MIT许可证。

```
MIT License

Copyright (c) 2025 Peauntxja

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
``` 