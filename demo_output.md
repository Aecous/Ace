# fscan gogo风格输出演示

## 🎯 **新的输出格式对比**

### **原始fscan输出:**
```
端口开放 192.168.1.50:80
服务识别 192.168.1.50:80 => [nginx] nginx v1.18.0 Banner: nginx/1.18.0

端口开放 192.168.1.50:5005
服务识别 192.168.1.50:5005 => [jdwp] Java Debug Wire Protocol
```

### **gogo原始输出:**
```
[+] tcp://192.168.1.50:139                       [open] \x83\x00\x00\x01\x8f  
[+] tcp://192.168.1.50:5005             focus:jdwp:active        [open] JDWP-Handshak [ info: jdwp_service payloads:path:JDWP-Handshake\n ]
```

### **新的fscan gogo风格输出:**
```
[+] tcp://192.168.1.50:80  focus:nginx:active [open] nginx/1.18.0 [ info: product:nginx version:1.18.0 fingertype:http ]

[+] tcp://192.168.1.50:5005  focus:jdwp:active [open] JDWP-Handshake [ info: fingertype:socket ]

[+] tcp://192.168.1.50:22  focus:ssh:active [open] SSH-2.0-OpenSSH_7.4 [ info: product:OpenSSH fingertype:socket ]

[+] tcp://192.168.1.50:3306  focus:mysql:active [open] \x00\x00\x00\x0a5.7.25 [ info: product:MySQL Database Server fingertype:socket ]

[+] tcp://192.168.1.50:139  [open]
```

## 🔍 **输出格式解析**

### **格式结构:**
```
[+] tcp://host:port  focus:service:status [open] response_data [ info: extra_info ]
```

### **字段说明:**
- **`[+] tcp://host:port`** - 类似gogo的协议和地址格式
- **`focus:service:status`** - 服务识别结果
  - `service`: 识别到的服务名称
  - `status`: `active`(置信度≥7) 或 `suspected`(置信度<7)
- **`[open]`** - 端口状态
- **`response_data`** - 原始响应内容
  - 可打印字符直接显示
  - 不可打印字符转换为十六进制格式(如 `\x83\x00\x00\x01`)
- **`[ info: ... ]`** - 额外信息
  - `product`: 产品名称
  - `version`: 版本号
  - `fingertype`: 指纹类型(http/socket/favicon)
  - `server`: 服务器信息
  - `vulnerability`: 漏洞信息(如JDWP未授权)

## 📊 **不同服务的输出示例**

### **Web服务器:**
```bash
# nginx
[+] tcp://192.168.1.100:80  focus:nginx:active [open] nginx/1.18.0 [ info: product:nginx version:1.18.0 fingertype:http server:nginx/1.18.0 ]

# Apache
[+] tcp://192.168.1.100:443  focus:apache:active [open] Apache/2.4.41 [ info: product:Apache HTTP Server fingertype:http server:Apache/2.4.41 ]

# 未知HTTP服务
[+] tcp://192.168.1.100:8080  focus:http:active [open] HTTP/1.1 200 OK [ info: product:HTTP Server fingertype:http ]
```

### **数据库服务:**
```bash
# MySQL
[+] tcp://192.168.1.100:3306  focus:mysql:active [open] \x00\x00\x00\x0a5.7.25-0ubuntu0... [ info: fingertype:socket ]

# Redis
[+] tcp://192.168.1.100:6379  focus:redis:active [open] +PONG [ info: fingertype:socket ]

# MongoDB
[+] tcp://192.168.1.100:27017  focus:mongodb:active [open] MongoDB shell version v4.2.8 [ info: fingertype:socket ]
```

### **远程服务:**
```bash
# SSH
[+] tcp://192.168.1.100:22  focus:ssh:active [open] SSH-2.0-OpenSSH_7.4 [ info: product:OpenSSH fingertype:socket ]

# Telnet
[+] tcp://192.168.1.100:23  focus:telnet:active [open] Ubuntu 18.04.5 LTS\nlogin: [ info: fingertype:socket ]
```

### **调试和开发工具:**
```bash
# JDWP未授权访问
[+] tcp://192.168.1.100:5005  focus:jdwp:active [open] JDWP-Handshake [ info: fingertype:socket vulnerability:JDWP未授权访问 ]

# Docker API
[+] tcp://192.168.1.100:2375  focus:docker-api:active [open] {"ApiVersion":"1.40"} [ info: fingertype:socket ]
```

### **端口开放但无服务识别:**
```bash
[+] tcp://192.168.1.100:8888  [open]
```

## 🎨 **主要改进特点**

1. **📍 gogo风格协议格式** - `[+] tcp://host:port`
2. **🔍 清晰的服务标识** - `focus:service:status`
3. **📊 原始响应显示** - 保留原始Banner内容
4. **🔧 智能十六进制转换** - 不可打印字符自动转换
5. **📋 结构化额外信息** - `[ info: key:value ]`格式
6. **⚡ 性能优化** - 简洁高效的检测逻辑

## 🆚 **与gogo的相似度**

| 特性 | gogo | 新版fscan | 相似度 |
|------|------|-----------|--------|
| **输出格式** | `[+] tcp://host:port` | `[+] tcp://host:port` | ✅ 100% |
| **服务识别** | `focus:service:status` | `focus:service:status` | ✅ 100% |
| **状态标识** | `[open]` | `[open]` | ✅ 100% |
| **响应显示** | 原始数据 | 原始数据+十六进制 | ✅ 95% |
| **额外信息** | `[ info: ... ]` | `[ info: ... ]` | ✅ 100% |

---

**🎊 现在fscan的输出格式已经高度接近gogo风格，同时保持了fscan的高性能和易用性！** 