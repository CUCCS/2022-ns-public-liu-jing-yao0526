# 实验五 基于 Scapy 编写端口扫描器

## 实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验要求

- 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
- 完成以下扫描技术的编程实现
  -  `TCP connect scan`/ `TCP stealth scan`
  -  `TCP Xmas scan` / `TCP fin scan`/ `TCP null scan`
  -  `UDP scan`
- 上述每种扫描技术的实现测试均需要测试端口状态为：开放、关闭 和 过滤 状态时的程序执行结果
- 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的

## 实验环境

- Visual Studio Code

- Scapy 2.4.4

- Kali Rolling (Linux kali 5.18.0-kali5-amd64)


## 实验步骤

### 网络拓扑

Attacker作为扫描端，Victim端作为被扫描的靶机，Gateway作为网关，起到联通作用。

![tp](img/tp.png)

### 端口状态模拟

查看当前防火墙的状态和现有规则

```bash
sudo ufw status
```

有以下三种状态

- 关闭状态：对应端口没有开启监听, 防火墙没有开启。

  ```shell
  sudo ufw disable
  ```

- 开启状态：对应端口开启监听: apache2基于TCP, 在80端口提供服务; DNS服务基于UDP,在53端口提供服务。防火墙处于关闭状态。

  ```shell
  systemctl start apache2 # port 80
  systemctl start dnsmasq # port 53
  ```

- 过滤状态：对应端口开启监听, 防火墙开启。

  ```bash
  ufw enable && ufw deny 80/tcp
  ufw enable && ufw deny 53/udp
  ```

### TCP connect scan

TCP connect Scan利用的是TCP协议的3次握手过程。它直接连到目标端口并完成一个完整的3次握手过程(SYN、SYN/ACK和ACK)。操作系统提供的“connect()”函数完成系统调用,用来与目标计算机的端口进行连接。若端口处于侦听状态，那么“connect()”函数就能成功。否则，这个端口是不能用的，即没有提供服务。先发送一个S，然后等待回应。如果有回应且标识为RA，说明目标端口处于关闭状态；如果有回应且标识为SA，说明目标端口处于开放状态。这时TCP connect scan会回复一个RA，在完成三次握手并断开连接。

**CODE**

```python
from scapy.all import *


def tcpconnect(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)
    if pkts is None:
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):  #Flags: 0x012 (SYN, ACK)
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=timeout)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):   #Flags: 0x014 (RST, ACK)
            print("Closed")

tcpconnect('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
sudo python tcp-connect-scan.py #运行python文件
```

![attacker-tcp-connect-scan-off](img/attacker-tcp-connect-scan-off.png)

victim端代码

```shell
sudo ufw status #检查防火墙状态，此处需要关闭
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

#### 端口开放

attacker端代码

```shell
sudo python tcp-connect-scan.py #运行python文件
```

![attacker-tcp-connect-scan-open](img/attacker-tcp-connect-scan-open.png)

victim端代码

```shell
systemctl start apache2 #打开TCP80监听端口
sudo ufw status #查看防火墙状态，此处状态需要关闭
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

![victim-tcp-connect-scan-open](img/victim-tcp-connect-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp-connect-scan.py #运行python文件
```

![attacker-tcp-connect-scan-filter](img/attacker-tcp-connect-scan-filter.png)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status #打开防火墙并且查看其状态
systemctl start apache2 # port 80，打开80端口
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

![victim-tcp-connect-scan-filter](img/victim-tcp-connect-scan-filter.png)

### TCP stealth scan

其原理是首先发送一个S，然后等待回应。如果有回应且标识为RA，则说明目标端口处于关闭状态；如果有回应且标识为SA，说明目标端口处于开放状态。这时TCP stealth scan只回复一个R，不完成三次握手，直接取消建立连接。

**CODE**

```python
#! /usr/bin/python

from scapy.all import *


def tcpstealthscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (pkts is None):
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")


tcpstealthscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
cd /home/kali/Desktop/code
sudo python tcp-stealth-scan.py
```

![attacker-tcp-stealth-scan-off](img/attacker-tcp-stealth-scan-off.png)

victim端代码

```shell
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-stealth-scan-off](img/victim-tcp-stealth-scan-off.png)

#### 端口开放

attacker端代码

```shell
sudo python tcp-stealth-scan.py
```

![attacker-tcp-stealth-scan-open](img/attacker-tcp-stealth-scan-open.png)

victim端代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R #开启抓包
sudo tshark -r tcp-scan-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-stealth-scan-open](img/victim-tcp-stealth-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp-stealth-scan.py
```

![attacker-tcp-stealth-scan-filter](img/attacker-tcp-stealth-scan-filter.png)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-stealth-scan-filter](img/victim-tcp-stealth-scan-filter.png)

### TCP Xmas scan

其原理在于TCP连接结束时,会向TCP端口发送一个设置了FIN 位的连接终止数据报,关闭的端口会回应一个设置了RST的连接复位数据报;而开放的端口则会对这种可疑的数据报不加理睬,将它丢弃。一种隐蔽性扫描，当处于端口处于关闭状态时，会回复一个RST包；其余所有状态都将不回复。

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def Xmasscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


Xmasscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
sudo python tcp-xmas-scan.py
```

![attacker-tcp-xmas-scan-off](img/attacker-tcp-xmas-scan-off.png)

victim端代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-xmas-scan-off](img/victim-tcp-xmas-scan-off.png)

#### 端口开放

attacker端代码

```shell
sudo ufw allow 80
sudo ufw allow 80/tcp
sudo python tcp-xmas-scan.py
```

![attacker-tcp-xmas-scan-open](img/attacker-tcp-xmas-scan-open.png)

victim端代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-xmas-scan-open](img/victim-tcp-xmas-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp-xmas-scan.py
```

![attacker-tcp-xmas-scan-filter](img/attacker-tcp-xmas-scan-filter.png)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-xmas-scan-filter](img/victim-tcp-xmas-scan-filter.png)

### TCP FIN scan

原理：当申请方主机向目标主机一个端口发送的TCP标志位FIN置位的数据包，如果目标主机该端口是“关”状态，则返回一个TCP RST数据包；否则不回复。根据这一原理可以判断对方端口是处于“开”还是“关”状态。这种方法的缺点是，该原理不是协议规定，因而与具体的协议系统实现有一定的关系，因为有些系统在实现的时候，不管端口是处于“开”还是“关”状态，都会回复RST数据包，从而导致此方法失效。只发送FIN包，FIN数据包能够通过只监测SYN包的包过滤器，隐蔽性较SYN扫描更⾼，此扫描与Xmas扫描也较为相似，只是发送的包未FIN包，同理，收到RST包说明端口处于关闭状态；反之说明为开启/过滤状态。

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def finscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


finscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
sudo python tcp-fin-scan.py
```

![attacker-tcp-fin-scan-off](img/attacker-tcp-fin-scan-off.png)

victim端代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-fin-scan-off](img/victim-tcp-fin-scan-off.png)

#### 端口开放

attacker端代码

```shell
sudo python tcp-fin-scan.py
```

![attacker-tcp-fin-scan-open](img/attacker-tcp-fin-scan-open.png)

victim端代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-fin-scan-open](img/victim-tcp-fin-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp-fin-scan.py
```

![attacker-tcp-fin-scan-filter](img/attacker-tcp-fin-scan-filter.png)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-fin-scan-filter](img/victim-tcp-fin-scan-filter.png)

### TCP NULL scan

原理是扫描主机向目标主机某端口发送一个带有FIN标志的数据包,如果目标主机端口未开,则会回应一个RST的连接复位数据报；而开放的端口则会对这种可疑的数据报不加理睬,将它丢弃。因此可以根据是否收到RST数据报来判断对方的端口是否开放。发送的包中关闭所有TCP报文头标记，实验结果预期同理：收到RST包说明端口为关闭状态，未收到包即为开启/过滤状态.

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def nullscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


nullscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
sudo python tcp-null-scan.py
```

![attacker-tcp-null-scan-off](img/attacker-tcp-null-scan-off.png)

victim端代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-null-scan-off](img/victim-tcp-null-scan-off.png)

#### 端口开放

attacker端代码

```shell
sudo python tcp-null-scan.py
```

![attacker-tcp-null-scan-open](img/attacker-tcp-null-scan-open.png)

victim端代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-null-scan-open](img/victim-tcp-null-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp-null-scan.py
```

![attacker-tcp-null-scan-filter](img/attacker-tcp-null-scan-filter.png)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w tcp-cnt-scan.pcap && date -R
sudo tshark -r tcp-cnt-scan.pcap -Y "tcp or udp or icmp"
```

![victim-tcp-null-scan-filter](img/victim-tcp-null-scan-filter.png)

### UDP scan

原理：由于UDP协议是非面向连接的，对UDP端口的探测，也就不可能像TCP端口的探测那样依赖于连接建立过程，这使得UDP端口扫描的可靠性不高。这是一种开放式扫描，通过发送UDP包进行扫描。当收到UDP回复时，该端口为开启状态；否则即为关闭/过滤状态。

**CODE**

```python
from scapy.all import *
def udpscan(dst_ip, dst_port, dst_timeout=10):
    resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    if (resp is None):
        print("Open|Filtered")
    elif (resp.haslayer(UDP)):
        print("Open")
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
            print("Closed")
        elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif(resp.haslayer(IP) and resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")
udpscan('10.0.2.6', 53)
```

#### 端口关闭

attacker端代码

```shell
sudo python udp_scan.py
```

![attacker-udp-scan-off](img/attacker-udp-scan-off.png)

victim端代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w udp_scan.pcap && date -R
sudo tshark -r udp_scan.pcap -Y "tcp or udp or icmp"
```

![victim-udp-scan-off](img/victim-udp-scan-off.png)

#### 端口开放

attacker端代码

```shell
sudo python udp_scan.py
```

![attacker-udp-scan-open-or-filter](img/attacker-udp-scan-open-or-filter.jpg)

victim端代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w udp_scan.pcap && date -R
sudo tshark -r udp_scan.pcap -Y "tcp or udp or icmp"
```

![victim-udp-scan-open](img/victim-udp-scan-open.png)

#### 端口过滤

attacker端代码

```shell
sudo python udp_scan.py
```

![attacker-udp-scan-open-or-filter](img/attacker-udp-scan-open-or-filter.jpg)

victim端代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth0 -w udp_scan.pcap && date -R
sudo tshark -r udp_scan.pcap -Y "tcp or udp or icmp"
```

![victim-udp-scan-filter](img/victim-udp-scan-filter.png)

提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
抓包以截图形式提供在每次扫描结果中。
完全相符。查看nmap文档，发现原理相同的。但是实操中nmap要快很多，分析是python调用包的问题。

## 实验问题及解决

查询防火墙状态时发现无该命令，安装后可以成功运行。

![ufw](img/ufw.png)

## 参考资料

[TCP Connect Scan (-sT) | Nmap Network Scanning](https://nmap.org/book/scan-methods-connect-scan.html)

[TCP SYN (Stealth) Scan (-sS) | Nmap Network Scanning](https://nmap.org/book/synscan.html)

[TCP FIN, NULL, and Xmas Scans (-sF, -sN, -sX) | Nmap Network Scanning](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html)

[UDP Scan (-sU) | Nmap Network Scanning](https://nmap.org/book/scan-methods-udp-scan.html)

[Guide: Using Scapy with Python - Santander Global Tech (santandergto.com)](https://santandergto.com/en/guide-using-scapy-with-python/)

[CUCCS/2021-ns-public-Lychee00: 2021-ns-public-Lychee00 created by GitHub Classroom](https://github.com/CUCCS/2021-ns-public-Lychee00)
