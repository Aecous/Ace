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

	"github.com/shadow1ng/fscan/Common"
)

// OptimizedGogoFinger 优化的gogo风格指纹识别器
type OptimizedGogoFinger struct {
	conn    net.Conn
	host    string
	port    int
	timeout time.Duration
	banner  string
	result  *GogoFingerResult
}

// OptimizedIdentifyService 优化的服务识别 - 复用连接，避免重复
func OptimizedIdentifyService(host string, port int, conn net.Conn, timeout time.Duration) *GogoFingerResult {
	finger := &OptimizedGogoFinger{
		conn:    conn,
		host:    host,
		port:    port,
		timeout: timeout,
	}

	return finger.identify()
}

// identify 执行识别流程 - 单连接，多重检测
func (f *OptimizedGogoFinger) identify() *GogoFingerResult {
	// 1. 快速读取Banner（减少超时时间）
	f.readBannerFast()

	// 2. 优先进行Socket指纹匹配
	if result := f.matchSocketFingers(); result != nil {
		return result
	}

	// 3. 如果看起来像HTTP，进行HTTP检测
	if f.looksLikeHTTP() {
		if result := f.probeHTTPOnExistingConnection(); result != nil {
			return result
		}
	}

	// 4. 基于端口的服务推测
	if result := f.guessServiceByPort(); result != nil {
		return result
	}

	return nil
}

// readBannerFast 快速读取Banner - 优化超时时间
func (f *OptimizedGogoFinger) readBannerFast() {
	// 设置较短的读取超时(500ms)
	f.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	buffer := make([]byte, 1024)
	n, _ := f.conn.Read(buffer)

	if n > 0 {
		f.banner = strings.TrimSpace(string(buffer[:n]))
	}
}

// matchSocketFingers 匹配Socket指纹 - 优化匹配顺序
func (f *OptimizedGogoFinger) matchSocketFingers() *GogoFingerResult {
	// 获取端口相关的指纹（优先匹配）
	priorityFingers := f.getPortSpecificFingers()

	// 优先匹配端口相关指纹
	for _, finger := range priorityFingers {
		if f.testSocketFinger(finger) {
			return f.createResult(finger)
		}
	}

	// 如果没有Banner，尝试主动探测
	if f.banner == "" {
		if result := f.activeProbe(); result != nil {
			return result
		}
	}

	return nil
}

// getPortSpecificFingers 获取端口相关的指纹 - 优化匹配效率
func (f *OptimizedGogoFinger) getPortSpecificFingers() []SocketFinger {
	var fingers []SocketFinger

	// 基于端口优先选择相关指纹
	for _, finger := range GogoEngine.SocketFingers {
		if len(finger.Port) == 0 {
			continue // 通用指纹最后处理
		}

		for _, p := range finger.Port {
			if p == f.port {
				fingers = append(fingers, finger)
				break
			}
		}
	}

	// 添加通用指纹
	for _, finger := range GogoEngine.SocketFingers {
		if len(finger.Port) == 0 {
			fingers = append(fingers, finger)
		}
	}

	return fingers
}

// testSocketFinger 测试Socket指纹
func (f *OptimizedGogoFinger) testSocketFinger(finger SocketFinger) bool {
	// 如果需要发送探测数据
	if finger.Probe != "" && f.banner == "" {
		probeData := f.decodeProbe(finger.Probe)
		if len(probeData) > 0 {
			f.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			f.conn.Write(probeData)

			f.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 1024)
			n, _ := f.conn.Read(buffer)
			if n > 0 {
				f.banner = strings.TrimSpace(string(buffer[:n]))
			}
		}
	}

	// 检查匹配模式
	for _, pattern := range finger.Match {
		matched, _ := regexp.MatchString(pattern, f.banner)
		if matched {
			return true
		}
	}

	return false
}

// looksLikeHTTP 判断是否像HTTP服务
func (f *OptimizedGogoFinger) looksLikeHTTP() bool {
	// 检查常见HTTP端口
	httpPorts := []int{80, 443, 8080, 8443, 8000, 8001, 8008, 8888, 9000, 9080, 7001, 7002}
	for _, p := range httpPorts {
		if p == f.port {
			return true
		}
	}

	// 检查Banner内容
	if f.banner != "" {
		lowerBanner := strings.ToLower(f.banner)
		httpKeywords := []string{"http/", "html", "server:", "content-type:", "connection:"}
		for _, keyword := range httpKeywords {
			if strings.Contains(lowerBanner, keyword) {
				return true
			}
		}
	}

	return false
}

// probeHTTPOnExistingConnection 在现有连接上进行HTTP探测
func (f *OptimizedGogoFinger) probeHTTPOnExistingConnection() *GogoFingerResult {
	// 如果Banner看起来已经是HTTP响应，直接分析
	if strings.Contains(f.banner, "HTTP/") {
		return f.analyzeHTTPResponse(f.banner, "http")
	}

	// 否则发送HTTP请求
	httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: fscan/2.0\r\nConnection: close\r\n\r\n", f.host)

	f.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := f.conn.Write([]byte(httpRequest))
	if err != nil {
		return nil
	}

	f.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := io.ReadAll(f.conn)
	if err != nil {
		return nil
	}

	responseStr := string(response)
	if strings.Contains(responseStr, "HTTP/") {
		return f.analyzeHTTPResponse(responseStr, "http")
	}

	return nil
}

// analyzeHTTPResponse 分析HTTP响应
func (f *OptimizedGogoFinger) analyzeHTTPResponse(response, scheme string) *GogoFingerResult {
	// 快速匹配HTTP指纹
	for _, finger := range GogoEngine.HTTPFingers {
		if f.matchHTTPFinger(finger, response) {
			result := &GogoFingerResult{
				Service:    finger.Name,
				Product:    finger.Name,
				Banner:     f.extractHTTPBanner(response),
				Protocol:   "tcp",
				Port:       f.port,
				Confidence: finger.Confidence,
				ExtraInfo:  make(map[string]string),
				FingerType: "http",
			}

			// 提取服务器信息
			if server := f.extractServerHeader(response); server != "" {
				result.ExtraInfo["server"] = server
			}

			return result
		}
	}

	// 通用HTTP服务
	result := &GogoFingerResult{
		Service:    "http",
		Product:    "HTTP Server",
		Banner:     f.extractHTTPBanner(response),
		Protocol:   "tcp",
		Port:       f.port,
		Confidence: 5,
		ExtraInfo:  make(map[string]string),
		FingerType: "http",
	}

	if server := f.extractServerHeader(response); server != "" {
		result.ExtraInfo["server"] = server
		result.Product = server
		result.Confidence = 7
	}

	return result
}

// matchHTTPFinger 匹配HTTP指纹
func (f *OptimizedGogoFinger) matchHTTPFinger(finger HTTPFinger, response string) bool {
	// 检查端口匹配
	if len(finger.Port) > 0 {
		portMatch := false
		for _, p := range finger.Port {
			if p == f.port {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	// 检查关键字匹配
	lowerResponse := strings.ToLower(response)
	for _, keyword := range finger.Keywords {
		if !strings.Contains(lowerResponse, strings.ToLower(keyword)) {
			return false
		}
	}

	// 检查响应头
	for _, header := range finger.Headers {
		if !strings.Contains(lowerResponse, strings.ToLower(header)) {
			return false
		}
	}

	return true
}

// extractHTTPBanner 提取HTTP Banner
func (f *OptimizedGogoFinger) extractHTTPBanner(response string) string {
	lines := strings.Split(response, "\n")
	if len(lines) > 0 {
		// 返回状态行
		statusLine := strings.TrimSpace(lines[0])
		if len(statusLine) > 100 {
			return statusLine[:97] + "..."
		}
		return statusLine
	}
	return ""
}

// extractServerHeader 提取Server头
func (f *OptimizedGogoFinger) extractServerHeader(response string) string {
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

// activeProbe 主动探测 - 仅在必要时使用
func (f *OptimizedGogoFinger) activeProbe() *GogoFingerResult {
	// 只对常见端口进行主动探测
	commonProbes := map[int]string{
		22:   "SSH-2.0-fscan\r\n",
		21:   "USER anonymous\r\n",
		25:   "EHLO fscan\r\n",
		5005: "JDWP-Handshake",
	}

	if probe, exists := commonProbes[f.port]; exists {
		f.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		f.conn.Write([]byte(probe))

		f.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 1024)
		n, _ := f.conn.Read(buffer)

		if n > 0 {
			f.banner = strings.TrimSpace(string(buffer[:n]))

			// 快速匹配
			if result := f.quickMatchByBanner(); result != nil {
				return result
			}
		}
	}

	return nil
}

// quickMatchByBanner 基于Banner快速匹配
func (f *OptimizedGogoFinger) quickMatchByBanner() *GogoFingerResult {
	if f.banner == "" {
		return nil
	}

	lowerBanner := strings.ToLower(f.banner)

	// 快速识别常见服务
	quickMatches := map[string][]string{
		"ssh":   {"ssh-"},
		"ftp":   {"220", "ftp"},
		"smtp":  {"220", "smtp", "mail"},
		"jdwp":  {"jdwp-handshake"},
		"mysql": {"mysql"},
		"redis": {"+pong", "-err"},
	}

	for service, keywords := range quickMatches {
		for _, keyword := range keywords {
			if strings.Contains(lowerBanner, keyword) {
				return &GogoFingerResult{
					Service:    service,
					Product:    service,
					Banner:     f.banner,
					Protocol:   "tcp",
					Port:       f.port,
					Confidence: 8,
					ExtraInfo:  make(map[string]string),
					FingerType: "socket",
				}
			}
		}
	}

	return nil
}

// guessServiceByPort 基于端口推测服务
func (f *OptimizedGogoFinger) guessServiceByPort() *GogoFingerResult {
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

	if service, exists := portServices[f.port]; exists {
		confidence := 4
		if f.banner != "" {
			confidence = 6 // 有Banner但未匹配指纹
		}

		return &GogoFingerResult{
			Service:    service,
			Product:    "Unknown " + service + " Service",
			Banner:     f.banner,
			Protocol:   "tcp",
			Port:       f.port,
			Confidence: confidence,
			ExtraInfo:  make(map[string]string),
			FingerType: "socket",
		}
	}

	return nil
}

// createResult 创建指纹识别结果
func (f *OptimizedGogoFinger) createResult(finger SocketFinger) *GogoFingerResult {
	return &GogoFingerResult{
		Service:    finger.Name,
		Product:    finger.Name,
		Banner:     f.banner,
		Protocol:   "tcp",
		Port:       f.port,
		Confidence: finger.Confidence,
		ExtraInfo:  make(map[string]string),
		FingerType: "socket",
	}
}

// decodeProbe 解码探测数据
func (f *OptimizedGogoFinger) decodeProbe(probe string) []byte {
	if strings.HasPrefix(probe, "\\x") {
		probe = strings.ReplaceAll(probe, "\\x", "")
		data, _ := hex.DecodeString(probe)
		return data
	}
	return []byte(probe)
}

// ===== 批量Favicon检测（可选功能，减少网络请求） =====

// BatchFaviconDetection 批量Favicon检测 - 可选启用
func BatchFaviconDetection(hosts []string, ports []int, timeout time.Duration) map[string]*GogoFingerResult {
	if !Common.EnableFingerprint {
		return nil
	}

	results := make(map[string]*GogoFingerResult)

	// 只对确认的HTTP服务进行Favicon检测
	for _, host := range hosts {
		for _, port := range ports {
			if isHTTPPort(port) {
				addr := fmt.Sprintf("%s:%d", host, port)
				if result := detectFaviconOptimized(host, port, timeout); result != nil {
					results[addr] = result
				}
			}
		}
	}

	return results
}

// detectFaviconOptimized 优化的Favicon检测
func detectFaviconOptimized(host string, port int, timeout time.Duration) *GogoFingerResult {
	schemes := []string{"http"}
	if port == 443 || port == 8443 {
		schemes = []string{"https", "http"}
	}

	for _, scheme := range schemes {
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout: timeout,
				}).DialContext,
			},
		}

		url := fmt.Sprintf("%s://%s:%d/favicon.ico", scheme, host, port)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			data, err := io.ReadAll(resp.Body)
			if err == nil && len(data) > 0 {
				hash := fmt.Sprintf("%x", md5.Sum(data))

				// 查找匹配的Favicon指纹
				for _, finger := range GogoEngine.FaviconFingers {
					if finger.Hash == hash {
						return &GogoFingerResult{
							Service:    finger.Name,
							Product:    finger.Product,
							Protocol:   "tcp",
							Port:       port,
							Confidence: finger.Confidence,
							ExtraInfo: map[string]string{
								"favicon_hash": hash,
							},
							FingerType: "favicon",
						}
					}
				}
			}
		}

		break // 成功连接就停止尝试其他协议
	}

	return nil
}
