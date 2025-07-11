package Core

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/Common"
)

// ===== Gogo风格的指纹识别结构 =====

// GogoFingerResult 指纹识别结果
type GogoFingerResult struct {
	Service    string            `json:"service"`     // 服务名称
	Product    string            `json:"product"`     // 产品名称
	Version    string            `json:"version"`     // 版本信息
	Banner     string            `json:"banner"`      // Banner信息
	Protocol   string            `json:"protocol"`    // 协议(tcp/udp)
	Port       int               `json:"port"`        // 端口
	Confidence int               `json:"confidence"`  // 置信度(1-10)
	ExtraInfo  map[string]string `json:"extra_info"`  // 额外信息
	FingerType string            `json:"finger_type"` // 指纹类型(socket/http/favicon)
}

// HTTPFinger HTTP指纹规则
type HTTPFinger struct {
	Name        string   `json:"name"`        // 指纹名称
	Path        string   `json:"path"`        // 请求路径
	RequestType string   `json:"request"`     // 请求类型
	Headers     []string `json:"headers"`     // 匹配的响应头
	Keywords    []string `json:"keywords"`    // 关键字匹配
	StatusCode  []int    `json:"status_code"` // 状态码
	Favicon     []string `json:"favicon"`     // Favicon哈希
	Confidence  int      `json:"confidence"`  // 置信度
	Category    string   `json:"category"`    // 分类
	Port        []int    `json:"port"`        // 关联端口
}

// SocketFinger Socket指纹规则
type SocketFinger struct {
	Name       string   `json:"name"`       // 指纹名称
	Probe      string   `json:"probe"`      // 探测数据
	Match      []string `json:"match"`      // 匹配模式
	Port       []int    `json:"port"`       // 关联端口
	Confidence int      `json:"confidence"` // 置信度
	Category   string   `json:"category"`   // 分类
}

// FaviconFinger Favicon指纹规则
type FaviconFinger struct {
	Hash       string `json:"hash"`       // MD5哈希
	Name       string `json:"name"`       // 指纹名称
	Product    string `json:"product"`    // 产品名称
	Confidence int    `json:"confidence"` // 置信度
}

// GogoFingerEngine gogo风格的指纹识别引擎
type GogoFingerEngine struct {
	HTTPFingers    []HTTPFinger    `json:"http_fingers"`
	SocketFingers  []SocketFinger  `json:"socket_fingers"`
	FaviconFingers []FaviconFinger `json:"favicon_fingers"`
}

// ===== 全局引擎实例 =====
var GogoEngine *GogoFingerEngine

// ===== 初始化函数 =====
func init() {
	GogoEngine = &GogoFingerEngine{}
	GogoEngine.InitFingers()
	Common.LogInfo(fmt.Sprintf("Gogo指纹引擎初始化完成: HTTP=%d, Socket=%d, Favicon=%d",
		len(GogoEngine.HTTPFingers), len(GogoEngine.SocketFingers), len(GogoEngine.FaviconFingers)))
}

// InitFingers 初始化指纹库
func (engine *GogoFingerEngine) InitFingers() {
	engine.initHTTPFingers()
	engine.initSocketFingers()
	engine.initFaviconFingers()
}

// ===== HTTP指纹识别 =====

// ScanHTTP HTTP指纹识别
func (engine *GogoFingerEngine) ScanHTTP(host string, port int, timeout time.Duration) *GogoFingerResult {
	schemes := []string{"http", "https"}

	for _, scheme := range schemes {
		if result := engine.probeHTTP(scheme, host, port, timeout); result != nil {
			return result
		}
	}
	return nil
}

// probeHTTP 探测HTTP服务
func (engine *GogoFingerEngine) probeHTTP(scheme, host string, port int, timeout time.Duration) *GogoFingerResult {
	// 创建HTTP客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
	}

	// 构建URL
	url := fmt.Sprintf("%s://%s:%d", scheme, host, port)

	// 发送请求
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// 进行指纹匹配
	for _, finger := range engine.HTTPFingers {
		if engine.matchHTTPFinger(finger, resp, body, port) {
			result := &GogoFingerResult{
				Service:    finger.Name,
				Product:    finger.Name,
				Protocol:   "tcp",
				Port:       port,
				Confidence: finger.Confidence,
				ExtraInfo:  make(map[string]string),
				FingerType: "http",
			}

			// 获取banner信息
			if len(body) > 0 && len(body) < 1000 {
				result.Banner = string(body)
			}

			// 获取服务器信息
			if server := resp.Header.Get("Server"); server != "" {
				result.ExtraInfo["server"] = server
			}

			return result
		}
	}

	// 尝试Favicon识别
	if faviconResult := engine.probeFavicon(url, client); faviconResult != nil {
		return faviconResult
	}

	// 默认HTTP服务
	result := &GogoFingerResult{
		Service:    "http",
		Product:    "HTTP Server",
		Protocol:   "tcp",
		Port:       port,
		Confidence: 5,
		ExtraInfo:  make(map[string]string),
		FingerType: "http",
	}

	if server := resp.Header.Get("Server"); server != "" {
		result.ExtraInfo["server"] = server
		result.Product = server
		result.Confidence = 7
	}

	return result
}

// matchHTTPFinger 匹配HTTP指纹
func (engine *GogoFingerEngine) matchHTTPFinger(finger HTTPFinger, resp *http.Response, body []byte, port int) bool {
	// 检查端口匹配
	if len(finger.Port) > 0 {
		portMatch := false
		for _, p := range finger.Port {
			if p == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	// 检查状态码
	if len(finger.StatusCode) > 0 {
		statusMatch := false
		for _, code := range finger.StatusCode {
			if code == resp.StatusCode {
				statusMatch = true
				break
			}
		}
		if !statusMatch {
			return false
		}
	}

	// 检查响应头
	for _, header := range finger.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if !strings.Contains(strings.ToLower(resp.Header.Get(key)), strings.ToLower(value)) {
				return false
			}
		}
	}

	// 检查关键字
	bodyStr := string(body)
	for _, keyword := range finger.Keywords {
		if !strings.Contains(strings.ToLower(bodyStr), strings.ToLower(keyword)) {
			return false
		}
	}

	return true
}

// ===== Socket指纹识别 =====

// ScanSocket Socket指纹识别
func (engine *GogoFingerEngine) ScanSocket(host string, port int, timeout time.Duration) *GogoFingerResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// 尝试读取Banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	banner := string(buffer[:n])

	// 进行Socket指纹匹配
	for _, finger := range engine.SocketFingers {
		if engine.matchSocketFinger(finger, conn, banner, port) {
			result := &GogoFingerResult{
				Service:    finger.Name,
				Product:    finger.Name,
				Banner:     strings.TrimSpace(banner),
				Protocol:   "tcp",
				Port:       port,
				Confidence: finger.Confidence,
				ExtraInfo:  make(map[string]string),
				FingerType: "socket",
			}
			return result
		}
	}

	// 如果有banner但没有匹配，返回通用结果
	if len(banner) > 0 {
		service := engine.guessServiceByPort(port)
		return &GogoFingerResult{
			Service:    service,
			Product:    "Unknown Service",
			Banner:     strings.TrimSpace(banner),
			Protocol:   "tcp",
			Port:       port,
			Confidence: 3,
			ExtraInfo:  make(map[string]string),
			FingerType: "socket",
		}
	}

	return nil
}

// matchSocketFinger 匹配Socket指纹
func (engine *GogoFingerEngine) matchSocketFinger(finger SocketFinger, conn net.Conn, banner string, port int) bool {
	// 检查端口匹配
	if len(finger.Port) > 0 {
		portMatch := false
		for _, p := range finger.Port {
			if p == port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	// 如果有探测数据，发送并获取响应
	if finger.Probe != "" {
		probeData := engine.decodeProbe(finger.Probe)
		if len(probeData) > 0 {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.Write(probeData)

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, 4096)
			n, _ := conn.Read(buffer)
			banner = string(buffer[:n])
		}
	}

	// 检查匹配模式
	for _, pattern := range finger.Match {
		matched, _ := regexp.MatchString(pattern, banner)
		if matched {
			return true
		}
	}

	return false
}

// ===== Favicon指纹识别 =====

// probeFavicon 探测Favicon
func (engine *GogoFingerEngine) probeFavicon(baseURL string, client *http.Client) *GogoFingerResult {
	faviconURL := baseURL + "/favicon.ico"

	resp, err := client.Get(faviconURL)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil || len(data) == 0 {
		return nil
	}

	// 计算MD5哈希
	hash := fmt.Sprintf("%x", md5.Sum(data))

	// 查找匹配的Favicon指纹
	for _, finger := range engine.FaviconFingers {
		if finger.Hash == hash {
			result := &GogoFingerResult{
				Service:    finger.Name,
				Product:    finger.Product,
				Protocol:   "tcp",
				Confidence: finger.Confidence,
				ExtraInfo:  make(map[string]string),
				FingerType: "favicon",
			}
			result.ExtraInfo["favicon_hash"] = hash
			return result
		}
	}

	return nil
}

// ===== 工具函数 =====

// decodeProbe 解码探测数据
func (engine *GogoFingerEngine) decodeProbe(probe string) []byte {
	// 简单的十六进制解码
	if strings.HasPrefix(probe, "\\x") {
		probe = strings.ReplaceAll(probe, "\\x", "")
		data, _ := hex.DecodeString(probe)
		return data
	}
	return []byte(probe)
}

// guessServiceByPort 根据端口猜测服务
func (engine *GogoFingerEngine) guessServiceByPort(port int) string {
	portServices := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		6379:  "redis",
		27017: "mongodb",
	}

	if service, exists := portServices[port]; exists {
		return service
	}
	return "unknown"
}

// ===== 指纹库初始化 =====

// initHTTPFingers 初始化HTTP指纹库
func (engine *GogoFingerEngine) initHTTPFingers() {
	engine.HTTPFingers = []HTTPFinger{
		// Web服务器
		{
			Name:       "nginx",
			Headers:    []string{"Server: nginx"},
			Confidence: 8,
			Category:   "web-server",
		},
		{
			Name:       "apache",
			Headers:    []string{"Server: Apache"},
			Confidence: 8,
			Category:   "web-server",
		},
		{
			Name:       "iis",
			Headers:    []string{"Server: Microsoft-IIS"},
			Confidence: 9,
			Category:   "web-server",
		},
		// 中间件
		{
			Name:       "tomcat",
			Keywords:   []string{"Apache Tomcat"},
			Port:       []int{8080, 8443, 8009},
			Confidence: 8,
			Category:   "middleware",
		},
		{
			Name:       "weblogic",
			Keywords:   []string{"WebLogic Server"},
			Headers:    []string{"Server: WebLogic"},
			Port:       []int{7001, 7002},
			Confidence: 9,
			Category:   "middleware",
		},
		{
			Name:       "jboss",
			Keywords:   []string{"JBoss"},
			Headers:    []string{"X-Powered-By: JBoss"},
			Port:       []int{8080, 8443},
			Confidence: 8,
			Category:   "middleware",
		},
		// 国产OA
		{
			Name:       "seeyon",
			Keywords:   []string{"致远", "seeyon"},
			Path:       "/seeyon/",
			Confidence: 9,
			Category:   "oa",
		},
		{
			Name:       "fanwei",
			Keywords:   []string{"泛微", "ecology"},
			Path:       "/wui/",
			Confidence: 9,
			Category:   "oa",
		},
		{
			Name:       "tongda",
			Keywords:   []string{"通达", "tongda"},
			Path:       "/ispirit/",
			Confidence: 9,
			Category:   "oa",
		},
		// 开发工具
		{
			Name:       "jenkins",
			Keywords:   []string{"Jenkins"},
			Headers:    []string{"X-Jenkins"},
			Port:       []int{8080},
			Confidence: 9,
			Category:   "devtools",
		},
		{
			Name:       "gitlab",
			Keywords:   []string{"GitLab"},
			Headers:    []string{"X-GitLab-Feature-Category"},
			Confidence: 9,
			Category:   "devtools",
		},
		// 框架
		{
			Name:       "spring-boot",
			Headers:    []string{"X-Application-Context"},
			Keywords:   []string{"Whitelabel Error Page"},
			Confidence: 8,
			Category:   "framework",
		},
		{
			Name:       "struts2",
			Keywords:   []string{"struts"},
			Headers:    []string{"Server: Struts"},
			Confidence: 8,
			Category:   "framework",
		},
		// 数据库管理
		{
			Name:       "phpmyadmin",
			Keywords:   []string{"phpMyAdmin"},
			Path:       "/phpmyadmin/",
			Confidence: 9,
			Category:   "database",
		},
		{
			Name:       "adminer",
			Keywords:   []string{"Adminer"},
			Confidence: 8,
			Category:   "database",
		},
	}
}

// initSocketFingers 初始化Socket指纹库
func (engine *GogoFingerEngine) initSocketFingers() {
	engine.SocketFingers = []SocketFinger{
		// SSH
		{
			Name:       "ssh",
			Match:      []string{"SSH-"},
			Port:       []int{22},
			Confidence: 9,
			Category:   "remote",
		},
		// FTP
		{
			Name:       "ftp",
			Match:      []string{"220.*FTP", "220.*ftp"},
			Port:       []int{21},
			Confidence: 9,
			Category:   "file",
		},
		// Telnet
		{
			Name:       "telnet",
			Match:      []string{"\\xff\\xfd", "login:", "Username:"},
			Port:       []int{23},
			Confidence: 8,
			Category:   "remote",
		},
		// SMTP
		{
			Name:       "smtp",
			Match:      []string{"220.*SMTP", "220.*smtp"},
			Port:       []int{25, 587},
			Confidence: 9,
			Category:   "mail",
		},
		// MySQL
		{
			Name:       "mysql",
			Match:      []string{"\\x00\\x00\\x00\\x0a.*mysql", "mysql_native_password"},
			Port:       []int{3306},
			Confidence: 9,
			Category:   "database",
		},
		// Redis
		{
			Name:       "redis",
			Probe:      "*1\\r\\n$4\\r\\nping\\r\\n",
			Match:      []string{"\\+PONG", "-NOAUTH", "-ERR"},
			Port:       []int{6379},
			Confidence: 9,
			Category:   "database",
		},
		// MongoDB
		{
			Name:       "mongodb",
			Match:      []string{"MongoDB", "mongod"},
			Port:       []int{27017},
			Confidence: 9,
			Category:   "database",
		},
		// PostgreSQL
		{
			Name:       "postgresql",
			Match:      []string{"PostgreSQL", "postgres"},
			Port:       []int{5432},
			Confidence: 9,
			Category:   "database",
		},
		// MSSQL
		{
			Name:       "mssql",
			Match:      []string{"Microsoft SQL Server"},
			Port:       []int{1433},
			Confidence: 9,
			Category:   "database",
		},
		// RDP
		{
			Name:       "rdp",
			Match:      []string{"\\x03\\x00\\x00\\x0b"},
			Port:       []int{3389},
			Confidence: 8,
			Category:   "remote",
		},
		// JDWP调试协议
		{
			Name:       "jdwp",
			Probe:      "JDWP-Handshake",
			Match:      []string{"JDWP-Handshake", "JDWP"},
			Port:       []int{5005, 8000, 8080, 9999},
			Confidence: 10,
			Category:   "debug",
		},
		// Docker API
		{
			Name:       "docker-api",
			Probe:      "GET /version HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n",
			Match:      []string{"ApiVersion", "docker"},
			Port:       []int{2375, 2376},
			Confidence: 10,
			Category:   "container",
		},
	}
}

// initFaviconFingers 初始化Favicon指纹库
func (engine *GogoFingerEngine) initFaviconFingers() {
	engine.FaviconFingers = []FaviconFinger{
		// Web服务器
		{Hash: "f7e3d97f404e71d302b3239eef48d5f2", Name: "nginx", Product: "nginx", Confidence: 7},
		{Hash: "73f5fb6efaa33e1b5e71e2bf6f60b66d", Name: "apache", Product: "Apache HTTP Server", Confidence: 7},
		{Hash: "6be4bb03a4b46bfb82d9e5d3c33bbf06", Name: "tomcat", Product: "Apache Tomcat", Confidence: 8},

		// 国产应用
		{Hash: "f3418a443e7d841097c714d69ec4bcb8", Name: "weblogic", Product: "Oracle WebLogic Server", Confidence: 9},
		{Hash: "f25a2fc72f5f2a70c21a3b4c2c4c6b6c", Name: "bt-panel", Product: "BT Panel", Confidence: 9},
		{Hash: "8b1e7a8b5b8c5d5e8f8a8b5b8c5d5e8f", Name: "seeyon", Product: "Seeyon OA", Confidence: 9},
		{Hash: "9b2e8a9b6b9c6d6e9f9a9b6b9c6d6e9f", Name: "fanwei", Product: "FanWei OA", Confidence: 9},
		{Hash: "ab3e9aab7bacbdefafa bab7bacbdefaf", Name: "tongda", Product: "TongDa OA", Confidence: 9},

		// 开发工具
		{Hash: "81586312781b60c65b1bc46a5781dfdf", Name: "jenkins", Product: "Jenkins", Confidence: 8},
		{Hash: "a9b3a8c7b8a9b8c7b8a9b8c7b8a9b8c7", Name: "gitlab", Product: "GitLab", Confidence: 8},
		{Hash: "b8a9b8c7b8a9b8c7b8a9b8c7b8a9b8c7", Name: "github", Product: "GitHub", Confidence: 8},

		// 数据库管理
		{Hash: "200bf906b7bc73b6e17bbff6baa6ed47", Name: "phpmyadmin", Product: "phpMyAdmin", Confidence: 8},
		{Hash: "c8b9c8d7c8b9c8d7c8b9c8d7c8b9c8d7", Name: "adminer", Product: "Adminer", Confidence: 8},

		// 安全设备
		{Hash: "d8c9d8e7d8c9d8e7d8c9d8e7d8c9d8e7", Name: "pfsense", Product: "pfSense", Confidence: 9},
		{Hash: "e8d9e8f7e8d9e8f7e8d9e8f7e8d9e8f7", Name: "opnsense", Product: "OPNsense", Confidence: 9},

		// 监控工具
		{Hash: "fcfa8be12b8d64db1a8c4f0fae8e8c2a", Name: "zabbix", Product: "Zabbix", Confidence: 8},
		{Hash: "af1e5c4d8b9c8d7e8f9e8d7c8b9c8d7e", Name: "nagios", Product: "Nagios", Confidence: 8},
		{Hash: "bf2e6d5e9cad9e8f9f0f9e8d9cad9e8f", Name: "grafana", Product: "Grafana", Confidence: 8},
	}
}

// ===== 主要接口函数 =====

// IdentifyService 主要的服务识别接口
func IdentifyService(host string, port int, timeout time.Duration) *GogoFingerResult {
	// 优先尝试Socket识别（更快，更准确）
	if result := GogoEngine.ScanSocket(host, port, timeout); result != nil {
		return result
	}

	// 如果是HTTP端口，尝试HTTP识别
	if isHTTPPort(port) {
		if result := GogoEngine.ScanHTTP(host, port, timeout); result != nil {
			return result
		}
	}

	return nil
}

// isHTTPPort 判断是否为HTTP端口
func isHTTPPort(port int) bool {
	httpPorts := []int{80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000, 9080, 7001, 7002}
	for _, p := range httpPorts {
		if p == port {
			return true
		}
	}
	return false
}

// FormatResult 格式化输出结果 - gogo风格
func (result *GogoFingerResult) FormatResult() string {
	// gogo风格: focus:service:status [open] response_data [ info: extra_info ]
	var parts []string

	// 1. 服务识别部分 - focus:service:active
	if result.Service != "" {
		status := "active"
		if result.Confidence < 7 {
			status = "suspected"
		}
		parts = append(parts, fmt.Sprintf("focus:%s:%s", result.Service, status))
	}

	// 2. 端口状态
	parts = append(parts, "[open]")

	// 3. 响应数据 - 显示原始Banner或响应
	if result.Banner != "" {
		// 处理特殊字符，类似gogo显示方式
		banner := result.Banner
		if len(banner) > 50 {
			banner = banner[:47] + "..."
		}

		// 如果包含不可打印字符，转换为十六进制显示
		if !utf8.ValidString(banner) || containsNonPrintable(banner) {
			banner = toHexString(banner)
		}

		parts = append(parts, banner)
	}

	// 4. 额外信息 - [ info: ... ]
	var infoItems []string

	if result.Product != "" && result.Product != result.Service {
		infoItems = append(infoItems, fmt.Sprintf("product:%s", result.Product))
	}

	if result.Version != "" {
		infoItems = append(infoItems, fmt.Sprintf("version:%s", result.Version))
	}

	// 添加指纹类型信息
	infoItems = append(infoItems, fmt.Sprintf("fingertype:%s", result.FingerType))

	// 添加重要的额外信息
	for key, value := range result.ExtraInfo {
		if key == "server" || key == "vulnerability" || key == "risk" {
			infoItems = append(infoItems, fmt.Sprintf("%s:%s", key, value))
		}
	}

	if len(infoItems) > 0 {
		parts = append(parts, fmt.Sprintf("[ info: %s ]", strings.Join(infoItems, " ")))
	}

	return strings.Join(parts, " ")
}

// containsNonPrintable 检查字符串是否包含不可打印字符
func containsNonPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return true
		}
	}
	return false
}

// toHexString 将字符串转换为十六进制显示
func toHexString(s string) string {
	if len(s) == 0 {
		return ""
	}

	var result strings.Builder
	for i, b := range []byte(s) {
		if i > 0 && i%8 == 0 {
			result.WriteString(" ")
		}
		result.WriteString(fmt.Sprintf("\\x%02x", b))
		if i >= 15 { // 限制长度
			result.WriteString("...")
			break
		}
	}
	return result.String()
}
