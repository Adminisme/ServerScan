# ServerScan

![Author](https://img.shields.io/badge/Author-Trim-blueviolet)  ![Bin](https://img.shields.io/badge/servercan-Bin-ff69b4)  ![build](https://img.shields.io/badge/build-passing-green.svg)  ![](https://img.shields.io/badge/language-golang-blue.svg)

# ServerScan

一款使用**Golang**开发且适用于攻防演习**内网横向信息收集**的**高并发**网络扫描、服务探测工具。

## 🍭Property
- 多平台支持（Window、Mac、Linux、Cobalt Strike）
- 存活IP探测（支持TCP、ICMP两种模式）
- 超快的端口扫描
- 新增服务和应用版本检测功能，采用内置指纹探针采用[nmap-service-probes](https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes)
- Web服务（http、https）信息探测
- ~~扫描结果兼容INFINITY攻防协同平台 （暂不公开）~~

## 🎉First Game

 总结诸多实战经验，考虑到实战过程中会出现和存在诸多复杂的环境，因此**ServerScan**设计了**轻巧版**、**专业版**、支持**Cobalt Strike跨平台beacon:[Cross C2](https://github.com/gloxec/CrossC2)的动态链接库**，以及支持~~**INFINITY攻防协同平台的专用版**~~。便于在不同的Shell环境中可以轻松自如的使用：如：Windows Cmd、Linux Console、远控Console、WebShell等，以及Cobalt Strike cna脚本文件加载和无文件落地的内存加载使用。

**轻巧版：**

 参数形式简单、扫描速度快耗时短、文件体积小、适合在网络情况较好条件情况下使用。

**专业版：**

 支持参数默认值、支持自定义扫描超时时长、支持扫描结果导出、适合在网络条件较苛刻的情况下使用。

**动态链接库：**

 为支持Cobalt Strike跨平台beacon，无文件落地，基于轻巧版本进行动态链接库编译，扫描超时时长为1.5秒。

### 💻for  Linux or Windows

  * #### 轻巧版
  
    * ***for PortScan***
    
      **Usage：**
    
      ![Air_scan_use](./img/serverscan/Linux/Air_scan_use.png)
    
      **Scanning：**
    
      ![Air_scan1](./img/serverscan/Linux/Air_scan.png)
    
    * ***for Service and Version Detection***
    
      **Usage：**
    
      ![Air_scan_probes_use](./img/serverscan/Windows/Air_scan_probes_use.png)
    
      **Scanning：**
    
      ![Air_scan_probes](./img/serverscan/Windows/Air_scan_probes.png)
  
  * #### 专业版

    * ***for PortScan***

      **Usage：**

      ![Pro_scan_use](./img/serverscan/Linux/Pro_scan_use.png)

      **Scanning：**
    
      ![Pro_scan](./img/serverscan/Linux/Pro_scan.png)
    
    * ***for Service and Version Detection***
    
      **Usage：**
    
      ![Pro_scan_probes_use](./img/serverscan/Windows/Pro_scan_probes_use.png)
    
      **Scanning：**
    
      ![Pro_scan_probes](./img/serverscan/Windows/Pro_scan_probes.png)

 

### 🎮for Cobalt Strike

  * ***can脚本***
  
  * for PortScan
    
  * for Service and Version Detection


  * ***Cobalt Strike跨平台beacon***

  * for PortScan

  * for Service and Version Detection



## 🌈Runtime Environment

为了实现**"一次开发，到处运行"**的效果，**ServerScan**采用具有跨平台编译特性的**Golang**进行开发。

目前已成功编译了**三大主流操作系统**的**可执行程序**和**动态链接库**，并在如下操作系统**通过**了运行测试：

#### 📺Windows

- **Windows 2003**
  - [x] **x86**

- **Windows 2008 server 、Windows 2012  server 、Windows 7 、Windows  10**
  - [x] **x86**
  - [x] **x64**
  - [x] **.dll**

#### 🐧Linux
- **Ubuntu 、Centos、Kali**
  - [x] **x86**
  - [x] **x64**
  - [x] **.so**

#### 🍎Mac OS
  - [x] **x64**
  - [x] **.dylib**


## 🐱‍👓Usage

* **轻巧版**

  ```shell
  HOST  Host to be scanned, supports four formats:
      192.168.1.1
      192.168.1.1-10
      192.168.1.*
      192.168.1.0/24
  PORT  Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ...
  MODEL Scan Model: icmp or tcp
  ```

* **专业版**

    ```shell
      -h string
          Host to be scanned, supports four formats:
          192.168.1.1
          192.168.1.1-10
          192.168.1.*
          192.168.1.0/24.
      -m string
          Scan Model icmp or tcp. (default "icmp")
      -o string
          Output the scanning information to file.
      -p string
          Customize port list, separate with ',' example: 21,22,80-99,8000-8080 ... (default "80-99,7000-9000,9001-9999,4430,1433,1521,3306,5000,5432,6379,21,22,100-500,873,4440,6082,3389,5560,5900-5909,1080,1900,10809,50030,50050,50070")
      -t int
          Setting scaner connection timeouts,Maxtime 3000 Millisecond. (default 1500)
      -v  ServerScan Build Version
    ```

* **Cobalt Strike版本**

  * can脚本

    

  * Hook - 无文件落地

    

* **INFINITY攻防协同平台版本**

   ~~（暂不公开）~~
  

## 🎁支持ServerScan

如果您认为ServerScan帮助到了您，想支持作者继续改进和优化ServerScan，可使用微信扫一扫下方的**赞赏码**。

<img src="./img/serverscan/thankyou.jpg" alt="thankyou" style="zoom: 33%;" />

## 💖鸣谢

一路走来，得到了很多前辈的帮助和指导，在此表示衷心的感谢！

下列是本项目使用或者参考的优秀开源框架，感谢网上众多的开源项目及其开源项目的作者，致敬每一位为网络安全事业做出贡献的每一位前辈！

* [httpscan](https://github.com/soxfmr/httpscan.go) - httpscan implements by Go
* [iprange](https://github.com/malfunkt/iprange) - IPv4 address parser for the nmap format
* [lanscan](https://github.com/stefanwichmann/lanscan) - Blazing fast, local network scanning in Go
* [vscan-go](https://github.com/RickGray/vscan-go) - Golang version for nmap service and application version detection

## 📄版权

 该项目未经作者本人允许，禁止商业性使用。

 任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担并将追究其相关责任！

## 📜免责声明

1. 本工具仅面向于合法授权的渗透测试安全人员以及进行常规操作的网络运维人员，用户可以合法且非商业目的地前提进行下载、传播、复制、使用本工具。

2. 本工具使用过程中，您应确保自己所有行为符合当地的法律法规，并且已经取得了足够的合法授权。

3. 不得将此软件用于从事违反中国人民共和国相关法律所禁止的活动，本工具所有作者和所有贡献者不承担用户擅自使用本工具从事的任何违法活动所产生的任何责任。

您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要下载并使用本工具。

您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。