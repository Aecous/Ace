package Core

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

// DynamicScanResult 动态扫描结果
type DynamicScanResult struct {
	Host      string                 `json:"host"`
	Port      int                    `json:"port"`
	Open      bool                   `json:"open"`
	Protocol  string                 `json:"protocol"` // tcp, http, https
	Status    string                 `json:"status"`   // open, 200, 404, etc.
	Title     string                 `json:"title"`
	Server    string                 `json:"server"`
	Banner    []byte                 `json:"banner"`
	IsHttp    bool                   `json:"is_http"`
	Error     string                 `json:"error,omitempty"`
	ExtraInfo map[string]interface{} `json:"extra_info"`
}

// DynamicProtocolScan 动态协议扫描 - 学习gogo的智能协议探测
func DynamicProtocolScan(host string, port int, timeout time.Duration) *DynamicScanResult {
	target := fmt.Sprintf("%s:%d", host, port)
	Common.LogDebug(fmt.Sprintf("开始动态协议扫描: %s (超时: %v)", target, timeout))

	result := &DynamicScanResult{
		Host:      host,
		Port:      port,
		ExtraInfo: make(map[string]interface{}),
	}

	// 1. 建立TCP连接
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	connectTime := time.Since(startTime)

	if err != nil {
		Common.LogDebug(fmt.Sprintf("动态扫描连接失败: %s - %v (耗时: %v)", target, err, connectTime))
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	Common.LogDebug(fmt.Sprintf("动态扫描连接成功: %s (耗时: %v)", target, connectTime))

	result.Open = true
	result.Status = "open"
	result.Protocol = "tcp" // 默认协议

	// 2. 尝试读取banner - 学习gogo的InitScan策略
	Common.LogDebug(fmt.Sprintf("开始读取banner: %s", target))
	bannerStart := time.Now()
	banner, err := readBannerWithTimeout(conn, timeout)
	bannerTime := time.Since(bannerStart)

	if err != nil {
		Common.LogDebug(fmt.Sprintf("banner读取失败，尝试HTTP探测: %s - %v (耗时: %v)", target, err, bannerTime))
		// 没有banner，尝试HTTP探测
		return tryHttpProbing(result, conn, target, timeout)
	}

	Common.LogDebug(fmt.Sprintf("banner读取成功: %s - 长度: %d 字节 (耗时: %v)", target, len(banner), bannerTime))
	Common.LogDebug(fmt.Sprintf("banner内容预览: %s - %q", target, string(banner)[:min(len(banner), 100)]))

	result.Banner = banner

	// 3. 分析banner判断协议
	Common.LogDebug(fmt.Sprintf("开始分析banner协议: %s", target))
	if isHttpBanner(banner) {
		Common.LogDebug(fmt.Sprintf("检测到HTTP banner: %s", target))
		return handleHttpBanner(result, banner, target, timeout)
	}

	// 4. 非HTTP协议，尝试HTTP探测确认
	Common.LogDebug(fmt.Sprintf("非HTTP banner，检查是否需要HTTP探测: %s", target))
	if shouldTryHttp(banner, port) {
		Common.LogDebug(fmt.Sprintf("需要HTTP探测，开始探测: %s", target))
		return tryHttpProbing(result, conn, target, timeout)
	}

	// 5. 确定为非HTTP协议，进行服务识别
	Common.LogDebug(fmt.Sprintf("确定为非HTTP协议，进行服务识别: %s", target))
	result.Protocol = identifyServiceFromBanner(string(banner), port)
	Common.LogDebug(fmt.Sprintf("服务识别完成: %s - 协议: %s", target, result.Protocol))
	return result
}

// readBannerWithTimeout 读取banner
func readBannerWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// isHttpBanner 判断是否为HTTP banner
func isHttpBanner(banner []byte) bool {
	bannerStr := string(banner)
	return strings.HasPrefix(bannerStr, "HTTP/") ||
		strings.Contains(bannerStr, "Content-Type:") ||
		strings.Contains(bannerStr, "Set-Cookie:")
}

// shouldTryHttp 判断是否应该尝试HTTP探测
func shouldTryHttp(banner []byte, port int) bool {
	// 空banner或特定端口总是尝试HTTP
	if len(banner) == 0 {
		return true
	}

	bannerStr := strings.ToLower(string(banner))

	// 包含可疑HTTP关键词
	httpKeywords := []string{"server:", "apache", "nginx", "iis", "tomcat", "jetty", "lighttpd"}
	for _, keyword := range httpKeywords {
		if strings.Contains(bannerStr, keyword) {
			return true
		}
	}

	return false
}

// handleHttpBanner 处理HTTP banner
func handleHttpBanner(result *DynamicScanResult, banner []byte, target string, timeout time.Duration) *DynamicScanResult {
	result.IsHttp = true
	result.Protocol = "http"

	// 解析HTTP响应
	lines := strings.Split(string(banner), "\n")
	if len(lines) > 0 {
		statusLine := strings.TrimSpace(lines[0])
		if strings.HasPrefix(statusLine, "HTTP/") {
			parts := strings.Split(statusLine, " ")
			if len(parts) >= 2 {
				result.Status = parts[1]
			}
		}
	}

	// 提取Server头
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			result.Server = strings.TrimSpace(line[7:])
			break
		}
	}

	return result
}

// tryHttpProbing 尝试HTTP探测 - 学习gogo的systemHttp策略
func tryHttpProbing(result *DynamicScanResult, conn net.Conn, target string, timeout time.Duration) *DynamicScanResult {
	Common.LogDebug(fmt.Sprintf("开始HTTP探测: %s", target))

	// 发送HTTP请求
	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; fscan/2.0)\r\nConnection: close\r\n\r\n", target)
	Common.LogDebug(fmt.Sprintf("发送HTTP请求: %s - 请求长度: %d 字节", target, len(httpRequest)))

	writeStart := time.Now()
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write([]byte(httpRequest))
	writeTime := time.Since(writeStart)

	if err != nil {
		Common.LogDebug(fmt.Sprintf("HTTP请求发送失败: %s - %v (耗时: %v)", target, err, writeTime))
		result.Error = err.Error()
		return result
	}

	Common.LogDebug(fmt.Sprintf("HTTP请求发送成功: %s (耗时: %v)", target, writeTime))

	// 读取HTTP响应
	Common.LogDebug(fmt.Sprintf("开始读取HTTP响应: %s", target))
	readStart := time.Now()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 10240) // 限制读取大小
	n, err := conn.Read(buf)
	readTime := time.Since(readStart)

	if err != nil {
		Common.LogDebug(fmt.Sprintf("HTTP响应读取失败: %s - %v (耗时: %v)", target, err, readTime))
		// HTTP请求失败，可能是其他协议
		return result
	}

	response := buf[:n]
	result.Banner = response

	Common.LogDebug(fmt.Sprintf("HTTP响应读取成功: %s - 长度: %d 字节 (耗时: %v)", target, len(response), readTime))
	Common.LogDebug(fmt.Sprintf("HTTP响应预览: %s - %q", target, string(response)[:min(len(response), 200)]))

	// 分析HTTP响应
	Common.LogDebug(fmt.Sprintf("开始分析HTTP响应: %s", target))
	if isHttpResponse(response) {
		Common.LogDebug(fmt.Sprintf("确认为HTTP响应，开始解析: %s", target))
		return parseHttpResponse(result, response, target, timeout)
	}

	Common.LogDebug(fmt.Sprintf("非标准HTTP响应: %s", target))
	return result
}

// isHttpResponse 判断是否为HTTP响应
func isHttpResponse(response []byte) bool {
	responseStr := string(response)
	return strings.HasPrefix(responseStr, "HTTP/") &&
		(strings.Contains(responseStr, "\r\n\r\n") || strings.Contains(responseStr, "\n\n"))
}

// parseHttpResponse 解析HTTP响应 - 实现gogo的智能协议切换
func parseHttpResponse(result *DynamicScanResult, response []byte, target string, timeout time.Duration) *DynamicScanResult {
	result.IsHttp = true
	result.Protocol = "http"

	responseStr := string(response)
	lines := strings.Split(responseStr, "\n")

	// 解析状态行
	if len(lines) > 0 {
		statusLine := strings.TrimSpace(lines[0])
		if strings.HasPrefix(statusLine, "HTTP/") {
			parts := strings.Split(statusLine, " ")
			if len(parts) >= 2 {
				result.Status = parts[1]
			}
		}
	}

	// 提取关键信息
	headerEndIndex := strings.Index(responseStr, "\r\n\r\n")
	if headerEndIndex == -1 {
		headerEndIndex = strings.Index(responseStr, "\n\n")
	}

	var headers string
	var body string
	if headerEndIndex != -1 {
		headers = responseStr[:headerEndIndex]
		body = responseStr[headerEndIndex+4:]
	} else {
		headers = responseStr
	}

	// 解析headers
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			result.Server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(strings.ToLower(line), "location:") && strings.Contains(line, "https") {
			// gogo风格：检测到HTTPS重定向
			result.Protocol = "https"
			result.ExtraInfo["redirect_to_https"] = true
		}
	}

	// 提取标题
	if body != "" {
		result.Title = extractTitleFromHtml(body)
	}

	// 智能协议判断 - 学习gogo策略
	if result.Status == "400" || (strings.HasPrefix(result.Status, "3") && result.Protocol != "https") {
		// 尝试HTTPS
		result.ExtraInfo["should_try_https"] = true
	}

	return result
}

// extractTitleFromHtml 从HTML中提取标题
func extractTitleFromHtml(html string) string {
	// 简化的标题提取
	titleStart := strings.Index(strings.ToLower(html), "<title")
	if titleStart == -1 {
		return ""
	}

	titleContentStart := strings.Index(html[titleStart:], ">")
	if titleContentStart == -1 {
		return ""
	}
	titleContentStart += titleStart + 1

	titleEnd := strings.Index(strings.ToLower(html[titleContentStart:]), "</title>")
	if titleEnd == -1 {
		return ""
	}
	titleEnd += titleContentStart

	title := strings.TrimSpace(html[titleContentStart:titleEnd])
	if len(title) > 100 {
		title = title[:100] + "..."
	}
	return title
}

// FastDynamicScan 快速动态扫描 - 集成到端口扫描流程
func FastDynamicScan(host string, port int) *DynamicScanResult {
	timeout := time.Duration(Common.Timeout) * time.Second
	result := DynamicProtocolScan(host, port, timeout)

	// 如果需要尝试HTTPS，进行二次探测
	if shouldTryHttps, exists := result.ExtraInfo["should_try_https"].(bool); exists && shouldTryHttps {
		httpsResult := tryHttpsRequest(host, port, timeout)
		if httpsResult != nil && httpsResult.IsHttp {
			// HTTPS成功，更新结果
			result.Protocol = "https"
			result.Status = httpsResult.Status
			result.Title = httpsResult.Title
			result.Server = httpsResult.Server
		}
	}

	return result
}

// tryHttpsRequest 尝试HTTPS请求
func tryHttpsRequest(host string, port int, timeout time.Duration) *DynamicScanResult {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("https://%s:%d", host, port)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result := &DynamicScanResult{
		Host:      host,
		Port:      port,
		Open:      true,
		IsHttp:    true,
		Protocol:  "https",
		Status:    fmt.Sprintf("%d", resp.StatusCode),
		Server:    resp.Header.Get("Server"),
		ExtraInfo: make(map[string]interface{}),
	}

	// 读取有限的响应体提取标题
	if resp.Body != nil {
		buf := make([]byte, 10240)
		n, _ := resp.Body.Read(buf)
		if n > 0 {
			result.Title = extractTitleFromHtml(string(buf[:n]))
		}
	}

	return result
}
