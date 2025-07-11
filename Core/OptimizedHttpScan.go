package Core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

// OptimizedHttpResult HTTP检测结果
type OptimizedHttpResult struct {
	URL         string            `json:"url"`
	StatusCode  int               `json:"status_code"`
	Title       string            `json:"title"`
	Server      string            `json:"server"`
	Length      int               `json:"length"`
	Protocol    string            `json:"protocol"`
	Banner      string            `json:"banner"`
	Headers     map[string]string `json:"headers"`
	Fingerprint string            `json:"fingerprint"`
	Error       string            `json:"error,omitempty"`
}

// OptimizedHttpScanner 优化的HTTP扫描器 - 学习gogo的单连接复用
type OptimizedHttpScanner struct {
	host        string
	port        int
	conn        net.Conn
	timeout     time.Duration
	fastTimeout time.Duration // gogo风格的快速超时
}

// NewOptimizedHttpScanner 创建优化的HTTP扫描器
func NewOptimizedHttpScanner(host string, port int, conn net.Conn) *OptimizedHttpScanner {
	return &OptimizedHttpScanner{
		host:        host,
		port:        port,
		conn:        conn,
		timeout:     2 * time.Second,        // 主要超时
		fastTimeout: 800 * time.Millisecond, // gogo风格快速超时
	}
}

// SmartHttpScan 智能HTTP扫描 - 整合gogo和fscanx的优化策略
func (scanner *OptimizedHttpScanner) SmartHttpScan() *OptimizedHttpResult {
	// 第一步：快速协议探测 - 学习fscanx的GetProtocol思路
	protocol := scanner.quickProtocolDetect()
	if protocol == "" {
		return scanner.createErrorResult("协议探测失败")
	}

	// 第二步：使用检测到的协议进行HTTP请求 - 学习gogo的智能选择
	if httpResult := scanner.performHttpRequest(protocol); httpResult != nil {
		return httpResult
	}

	// 第三步：如果HTTP失败且协议是http，尝试HTTPS - gogo的fallback策略
	if protocol == "http" {
		if httpsResult := scanner.performHttpRequest("https"); httpsResult != nil {
			return httpsResult
		}
	}

	return scanner.createErrorResult("HTTP检测失败")
}

// quickProtocolDetect 快速协议探测 - 基于fscanx的GetProtocol优化
func (scanner *OptimizedHttpScanner) quickProtocolDetect() string {
	// 常见端口快速判断
	switch scanner.port {
	case 443, 8443, 9443:
		return "https"
	case 80, 8000, 8080, 8081, 8090:
		return "http"
	}

	// socket探测 - 学习gogo的InitScan方式
	scanner.conn.SetReadDeadline(time.Now().Add(scanner.fastTimeout))

	// 发送简单HTTP请求探测
	httpProbe := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", scanner.host)
	scanner.conn.SetWriteDeadline(time.Now().Add(scanner.fastTimeout))

	_, err := scanner.conn.Write([]byte(httpProbe))
	if err != nil {
		return "http" // 默认尝试HTTP
	}

	// 读取响应判断协议
	buffer := make([]byte, 1024)
	scanner.conn.SetReadDeadline(time.Now().Add(scanner.fastTimeout))
	n, err := scanner.conn.Read(buffer)

	if err == nil && n > 0 {
		response := string(buffer[:n])
		if strings.Contains(response, "HTTP/") {
			return "http"
		}
		if strings.Contains(response, "400 Bad Request") ||
			strings.Contains(response, "SSL") ||
			strings.Contains(response, "TLS") {
			return "https"
		}
	}

	// 默认返回http
	return "http"
}

// performHttpRequest 执行HTTP请求 - 学习gogo的systemHttp优化
func (scanner *OptimizedHttpScanner) performHttpRequest(scheme string) *OptimizedHttpResult {
	client := scanner.createOptimizedClient(scheme)
	url := fmt.Sprintf("%s://%s:%d", scheme, scanner.host, scanner.port)

	// 创建请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// 设置请求头 - 学习fscanx的最小化请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; fscan/2.0)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("HTTP请求失败 %s: %v", url, err))
		return nil
	}
	defer resp.Body.Close()

	// 解析响应
	return scanner.parseHttpResponse(resp, scheme)
}

// createOptimizedClient 创建优化的HTTP客户端 - 基于fscanx的客户端配置
func (scanner *OptimizedHttpScanner) createOptimizedClient(scheme string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: scanner.fastTimeout, // 使用快速超时
		TLSHandshakeTimeout:   scanner.fastTimeout,
		MaxIdleConns:          0,
		IdleConnTimeout:       0,
		DisableCompression:    true, // 禁用压缩加快速度
	}

	return &http.Client{
		Transport: transport,
		Timeout:   scanner.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 限制重定向次数，提高速度
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// parseHttpResponse 解析HTTP响应 - 整合gogo和fscanx的解析逻辑
func (scanner *OptimizedHttpScanner) parseHttpResponse(resp *http.Response, scheme string) *OptimizedHttpResult {
	result := &OptimizedHttpResult{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Protocol:   scheme,
		Headers:    make(map[string]string),
	}

	// 提取关键响应头
	result.Server = resp.Header.Get("Server")
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		result.Headers["Content-Length"] = contentLength
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		result.Headers["Content-Type"] = contentType
	}

	// 读取响应体 - 限制大小提高速度
	body, err := scanner.readLimitedBody(resp.Body, 10240) // 最大10KB
	if err != nil {
		result.Error = fmt.Sprintf("读取响应体失败: %v", err)
		return result
	}

	result.Length = len(body)

	// 提取标题 - 使用优化的正则表达式
	if title := scanner.extractTitle(body); title != "" {
		result.Title = title
	}

	// 快速指纹识别 - 基于关键特征
	result.Fingerprint = scanner.quickFingerprint(resp, body)

	return result
}

// readLimitedBody 限制读取的响应体大小
func (scanner *OptimizedHttpScanner) readLimitedBody(body io.ReadCloser, maxSize int64) ([]byte, error) {
	limitedReader := io.LimitReader(body, maxSize)
	return io.ReadAll(limitedReader)
}

// extractTitle 快速提取网页标题
func (scanner *OptimizedHttpScanner) extractTitle(body []byte) string {
	// 只在前2048字节中查找标题，提高速度
	searchLen := len(body)
	if searchLen > 2048 {
		searchLen = 2048
	}

	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,100})</title>`)
	matches := titleRegex.FindSubmatch(body[:searchLen])
	if len(matches) > 1 {
		title := strings.TrimSpace(string(matches[1]))
		return title
	}
	return ""
}

// quickFingerprint 快速指纹识别 - 基于关键特征匹配
func (scanner *OptimizedHttpScanner) quickFingerprint(resp *http.Response, body []byte) string {
	server := strings.ToLower(resp.Header.Get("Server"))
	bodyStr := strings.ToLower(string(body))

	// 快速匹配常见应用
	fingerprints := []struct {
		name      string
		condition func() bool
	}{
		{"nginx", func() bool { return strings.Contains(server, "nginx") }},
		{"apache", func() bool { return strings.Contains(server, "apache") }},
		{"iis", func() bool { return strings.Contains(server, "iis") }},
		{"tomcat", func() bool {
			return strings.Contains(server, "tomcat") || strings.Contains(bodyStr, "apache tomcat")
		}},
		{"weblogic", func() bool {
			return strings.Contains(server, "weblogic") || strings.Contains(bodyStr, "weblogic")
		}},
		{"jenkins", func() bool {
			return strings.Contains(bodyStr, "jenkins") && strings.Contains(bodyStr, "build")
		}},
		{"gitlab", func() bool {
			return strings.Contains(bodyStr, "gitlab")
		}},
		{"jboss", func() bool {
			return strings.Contains(server, "jboss") || strings.Contains(bodyStr, "jboss")
		}},
	}

	for _, fp := range fingerprints {
		if fp.condition() {
			return fp.name
		}
	}

	return "unknown"
}

// createErrorResult 创建错误结果
func (scanner *OptimizedHttpScanner) createErrorResult(errMsg string) *OptimizedHttpResult {
	return &OptimizedHttpResult{
		URL:   fmt.Sprintf("http://%s:%d", scanner.host, scanner.port),
		Error: errMsg,
	}
}

// OptimizedHttpDetect 主要的HTTP检测函数 - 供外部调用
func OptimizedHttpDetect(host string, port int, conn net.Conn) *OptimizedHttpResult {
	scanner := NewOptimizedHttpScanner(host, port, conn)
	result := scanner.SmartHttpScan()

	// 格式化输出 - 学习gogo的简洁输出风格
	if result.Error == "" {
		logMsg := fmt.Sprintf("[+] %s [%d] %s",
			result.URL, result.StatusCode, result.Title)
		if result.Server != "" {
			logMsg += fmt.Sprintf(" [%s]", result.Server)
		}
		if result.Fingerprint != "unknown" {
			logMsg += fmt.Sprintf(" {%s}", result.Fingerprint)
		}
		Common.LogSuccess(logMsg)
	}

	return result
}

// BatchOptimizedHttpScan 批量HTTP扫描 - 提供批量接口
func BatchOptimizedHttpScan(targets []struct {
	Host string
	Port int
	Conn net.Conn
}) []*OptimizedHttpResult {
	results := make([]*OptimizedHttpResult, len(targets))

	for i, target := range targets {
		results[i] = OptimizedHttpDetect(target.Host, target.Port, target.Conn)
	}

	return results
}
