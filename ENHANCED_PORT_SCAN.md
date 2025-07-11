# fscan 增强端口扫描功能

## 🚀 **新功能概览**

基于对gogo项目的深入分析，我们为fscan添加了全新的增强端口扫描功能：

### ✨ **核心增强特性**
- **TCP连接 + Banner获取** - 学习gogo的连接方式，自动读取服务Banner
- **智能协议识别** - 自动识别HTTP/HTTPS，支持协议自动切换
- **未授权服务检测** - 内置常见未授权访问漏洞检测
- **速率控制集成** - 完美集成我们的智能速率控制系统
- **详细结果记录** - 记录Banner、标题、响应头、漏洞信息等

## 📊 **技术实现亮点**

### **学习gogo的优势**
```go
// 1. TCP连接后自动Banner读取
conn, err := net.DialTimeout("tcp", target, timeout)
banner := readBanner(conn)

// 2. 如果没有Banner，发送HTTP探测
if banner == "" || looksLikeHttp(banner, port) {
    probeHttp(result)
}

// 3. 自动协议识别
if resp.TLS != nil {
    result.Protocol = "https"
} else {
    result.Protocol = "http"
}
```

### **集成速率控制**
```go
// 在每个扫描任务中应用智能速率控制
Common.SmartWait()

// 支持三种模式：fast, balanced, stealth
// 自动进行随机抖动和突发控制
```

## 🎯 **fscan增强端口扫描功能** ⭐ **v2.1新增**

### **核心特性**

✅ **TCP连接+Banner获取** - 学习gogo的连接方式  
✅ **智能协议识别** - HTTP/HTTPS自动切换  
✅ **未授权服务检测** - 9种主要服务类型  
✅ **精确速率控制** - 基于令牌桶算法  
✅ **JDWP调试协议检测** ⭐ **新增**  
✅ **全面TCP服务识别** ⭐ **新增v2.1**

---

## 🔍 **v2.1新增：全面TCP服务检测**

基于对gogo扫描器的深入研究，我们现在对**所有开放的TCP端口**进行全面的服务识别和安全检测：

### **智能Banner获取策略**
- **被动Banner获取** - 直接读取服务主动发送的Banner
- **主动协议探测** - 根据端口发送特定探测包
- **多协议支持** - HTTP、SSH、FTP、SMTP、POP3、IMAP、Telnet等
- **通用TCP探测** - 对所有端口发送通用探测包

### **扩展的服务识别能力**
支持识别**50+种服务类型**，包括：

| 服务类型 | 检测方式 | 安全检查 |
|----------|----------|----------|
| **SSH** | Banner解析 | 版本信息提取 |
| **FTP** | 协议交互 | 匿名登录检测 |
| **MySQL** | Banner识别 | 版本信息提取 |
| **Redis** | INFO命令 | 未授权访问检测 |
| **MongoDB** | Banner解析 | 未授权访问检测 |
| **PostgreSQL** | Banner识别 | 版本信息提取 |
| **Elasticsearch** | HTTP请求 | 未授权访问检测 |
| **Memcached** | stats命令 | 未授权访问检测 |
| **Oracle** | Banner解析 | TNS监听器检测 |
| **MSSQL** | Banner识别 | 版本信息提取 |
| **LDAP** | Banner解析 | 目录服务检测 |
| **VNC** | RFB协议 | 无密码检测 |
| **RDP** | 端口识别 | 远程桌面检测 |
| **SMB** | 端口识别 | 文件共享检测 |
| **JDWP** ⭐ | 握手协议 | **Java调试未授权** |

### **未知服务智能处理**
- **tcp-banner** - 有Banner但无法识别的服务
- **tcp-unknown** - 无Banner的开放端口
- **http-like** - 疑似HTTP服务的进一步探测
- **版本信息提取** - 从Banner中提取版本号

---

## 🎯 **未授权服务检测**

### **支持的服务类型**
| 端口 | 服务 | 检测内容 |
|------|------|----------|
| **2375/2376** | Docker API | `/version` 接口未授权访问 |
| **8080/8081/8090** | Web服务 | Spring Boot Actuator、Jolokia等 |
| **9200/9300** | Elasticsearch | 集群信息未授权访问 |
| **6379** | Redis | INFO命令未授权执行 |
| **11211** | Memcached | stats命令未授权访问 |
| **27017/27018** | MongoDB | 连接未授权访问 |
| **5984/5985** | CouchDB | 数据库信息未授权访问 |
| **3000** | Grafana/Jenkins | 默认配置和未授权访问 |

### **检测示例**
```bash
# Docker API未授权检测
GET http://target:2375/version
Response: {"Version":"20.10.8"...}
Result: ✅ Docker API未授权访问

# Spring Boot Actuator检测  
GET http://target:8080/actuator/health
Response: {"status":"UP"...}
Result: ✅ Spring Boot Actuator未授权

# Redis未授权检测
Command: INFO
Response: redis_version:6.2.6...
Result: ✅ Redis未授权访问

# JDWP Java调试协议检测 ⭐ 新增
TCP Send: JDWP-Handshake
TCP Response: JDWP-Handshake
Command: Version (0x0101)
Response: JVM Version Info...
Result: ✅ JDWP Java调试协议未授权访问 (极高风险!)

# 全面TCP服务识别 ⭐ v2.1新增
TCP Connect: 192.168.1.100:3306
Banner Probe: Generic + MySQL specific
Response: MySQL 5.7.34-log ready for connections
Result: ✅ 识别为mysql服务，版本5.7.34
```

---

## 🔧 **使用方式**

### **代码中调用**
```go
// 使用新的增强端口扫描
scanner := NewEnhancedPortScanner()
results := scanner.ScanPorts(hosts, ports)

// 或者使用兼容接口
addresses := NewEnhancedPortScan(hosts, "1-1000", 5)
```

### **命令行使用**
```bash
# 快速扫描模式（最大化速度）
fscan -h 192.168.1.0/24 -p 1-1000 -rmode fast -prate 0.8

# 平衡扫描模式（推荐）
fscan -h 192.168.1.0/24 -p 1-1000 -rmode balanced -prate 0.3

# 隐蔽扫描模式（最强反检测）
fscan -h 192.168.1.0/24 -p 1-1000 -rmode stealth -prate 0.1
```

## 📈 **扫描结果格式**

### **端口结果结构**
```json
{
  "host": "192.168.1.100",
  "port": 8080,
  "status": "open",
  "protocol": "http",
  "service": "http",
  "banner": "HTTP/1.1 200 OK\nServer: Apache/2.4.41",
  "title": "Spring Boot Application",
  "headers": {
    "status": "200",
    "server": "Apache/2.4.41"
  },
  "vulns": [
    "Spring Boot Actuator未授权"
  ]
}
```

### **日志输出示例**
```
[INFO] 发现端口: 192.168.1.100:8080 [http] 标题:Spring Boot Application
[ERROR] 发现端口: 192.168.1.100:2375 [docker-api] 漏洞:Docker API未授权访问
[INFO] 发现端口: 192.168.1.100:22 [ssh] Banner:SSH-2.0-OpenSSH_8.3
[ERROR] 发现端口: 192.168.1.100:6379 [redis] 漏洞:Redis未授权访问
[ERROR] 发现端口: 192.168.1.100:8787 [jdwp] 漏洞:JDWP Java调试协议未授权访问
[INFO] 发现端口: 192.168.1.100:3306 [mysql] Banner:MySQL 5.7.34-log
[INFO] 发现端口: 192.168.1.100:5432 [postgresql] Banner:PostgreSQL ready
[ERROR] 发现端口: 192.168.1.100:9200 [elasticsearch] 漏洞:Elasticsearch未授权访问
[INFO] 发现端口: 192.168.1.100:1234 [tcp-banner] Banner:Custom Service v1.0
[INFO] 发现端口: 192.168.1.100:9999 [tcp-unknown] 无Banner开放端口
```

---

## ⚡ **性能优势**

### **与原版fscan对比**
| 特性 | 原版fscan | 增强版本 |
|------|-----------|----------|
| **连接方式** | 简单TCP连接测试 | TCP + Banner + HTTP探测 |
| **协议识别** | 基于nmap-probes复杂系统 | 简化的智能识别 |
| **漏洞检测** | 需要额外插件 | 内置未授权检测 |
| **速率控制** | 硬编码并发限制 | 智能速率控制 |
| **结果详细度** | 基础端口状态 | 完整服务信息 |

### **与gogo对比**
| 特性 | gogo | 我们的实现 |
|------|------|------------|
| **扫描方式** | TCP + HTTP + 深度指纹 | TCP + HTTP + 基础指纹 |
| **速率控制** | 固定延迟 | 智能令牌桶 |
| **反检测** | 无 | 随机抖动 + 突发 |
| **未授权检测** | 无 | 专门针对性检测 |
| **集成度** | 独立工具 | 完美集成fscan |

## 🎯 **实战应用场景**

### **内网资产发现**
```bash
# 快速发现内网Web服务和API
fscan -h 10.0.0.0/8 -p 80,443,8080,8081,8090,3000 -rmode fast
# 重点关注：Docker API、Spring Boot、Grafana等
```

### **外网渗透测试**
```bash
# 隐蔽扫描目标服务
fscan -h target.com -p 1-65535 -rmode stealth -prate 0.05
# 重点关注：未授权服务、默认配置、敏感端口
```

### **安全基线检查**
```bash
# 检查生产环境未授权访问
fscan -h production_network.txt -p 2375,6379,9200,11211,27017 -rmode balanced
# 重点关注：数据库、缓存、API等关键服务
```

### **Java环境专项检测** ⭐ **新增**
```bash
# 专门检测Java调试接口和相关服务
fscan -h java_servers.txt -p 8000,8787,9999,8080,8081,8090 -rmode stealth
# 重点关注：JDWP调试接口、Spring Boot应用、Java Web服务
# 风险提示：JDWP未授权可直接获取JVM控制权，执行任意代码！
```

---

### **检测原理详解**

### **Banner识别流程**
1. **TCP连接建立** - 标准三次握手
2. **自动Banner读取** - 5秒超时等待服务主动发送Banner
3. **服务特征匹配** - 基于关键字识别常见服务
4. **端口默认推断** - 根据端口号推测可能的服务

### **HTTP探测流程**
1. **HTTP端口判断** - 检查是否为常见HTTP端口
2. **HTTPS优先尝试** - 先尝试HTTPS连接
3. **HTTP降级** - HTTPS失败后尝试HTTP
4. **标题提取** - 自动提取网页标题信息
5. **响应头分析** - 记录Server等关键信息

### **未授权检测原理**
1. **服务识别** - 基于端口和Banner确定服务类型
2. **特定请求** - 发送服务特定的检测请求
3. **响应分析** - 分析响应内容判断是否存在未授权访问
4. **漏洞确认** - 确认漏洞存在并记录详细信息

### **JDWP检测原理详解** ⭐ **新增**
1. **握手检测** - 发送`JDWP-Handshake`字符串
2. **协议验证** - 检查是否返回相同握手响应
3. **命令探测** - 发送Version命令(CommandSet=1, Command=1)
4. **响应解析** - 分析JDWP协议格式：
   - 包长度(4字节) + 包ID(4字节) + 标志位(1字节)
   - 验证响应标志位0x80(响应包标识)
   - 提取JVM版本信息进行确认
5. **风险评估** - JDWP未授权属于极高风险漏洞

### **全面TCP检测原理** ⭐ **v2.1新增**
1. **TCP连接建立** - 对每个开放端口建立TCP连接
2. **被动Banner获取** - 读取服务主动发送的Banner信息
3. **主动协议探测** - 根据端口类型发送特定探测包
4. **智能服务识别** - 基于Banner特征和端口号识别服务类型
5. **安全风险检测** - 针对识别出的服务进行安全检查
6. **未知服务处理** - 对无法识别的服务进行通用检测

---

## 🛡️ **安全考虑**

### **流量特征**
- ✅ **随机抖动**: 避免固定频率被检测
- ✅ **突发模拟**: 模拟正常网络流量特征  
- ✅ **速率控制**: 可调节的扫描速度
- ✅ **连接复用**: 减少连接建立开销

### **检测规避**
- 🔧 **User-Agent伪装**: 使用常见浏览器标识
- 🔧 **请求头正常化**: 模拟真实HTTP请求
- 🔧 **超时控制**: 避免长时间连接引起注意
- 🔧 **错误处理**: 优雅处理连接失败和异常

---

## 💡 **总结**

通过学习gogo的TCP连接和Banner获取方式，我们成功创建了一个**快速、智能、隐蔽**的端口扫描解决方案：

- **保持fscan的高效性** - 基于令牌桶的精确速率控制
- **增加gogo的智能性** - TCP + Banner + HTTP自动探测  
- **添加专业的安全性** - 针对性的未授权服务检测
- **提供完美的集成性** - 无缝集成到现有fscan架构
- **新增JDWP检测能力** ⭐ - 检测Java调试协议未授权访问(极高风险)
- **全面TCP服务识别** ⭐ **v2.1** - 对所有TCP端口进行深度服务识别

这个增强版本特别适合**渗透测试、安全评估、资产发现、Java环境安全检查**等实战场景，能够在保持高速扫描的同时提供详细的服务信息和安全风险提示。

**特别提醒**: JDWP未授权访问是极其危险的漏洞，可直接获取目标JVM完全控制权，务必重点关注！

**v2.1更新**: 现在支持对所有TCP端口进行全面的服务识别和Banner获取，大幅提升了服务发现能力，真正做到了像gogo一样的全面TCP检测！ 