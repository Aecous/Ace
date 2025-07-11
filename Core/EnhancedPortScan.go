package Core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/shadow1ng/fscan/Common"
)

// PortResult 端口扫描结果
type PortResult struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Status   string            `json:"status"`
	Protocol string            `json:"protocol"`
	Service  string            `json:"service"`
	Banner   string            `json:"banner,omitempty"`
	Title    string            `json:"title,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Vulns    []string          `json:"vulns,omitempty"`
}

// EnhancedPortScanner 增强端口扫描器
type EnhancedPortScanner struct {
	timeout     time.Duration
	httpTimeout time.Duration
	maxBanner   int
}

// NewEnhancedPortScanner 创建增强端口扫描器
func NewEnhancedPortScanner() *EnhancedPortScanner {
	return &EnhancedPortScanner{
		timeout:     time.Duration(Common.Timeout) * time.Second,
		httpTimeout: time.Duration(Common.Timeout+2) * time.Second,
		maxBanner:   2048,
	}
}

// ScanPorts 扫描端口列表 - 学习gogo的高效方式
func (s *EnhancedPortScanner) ScanPorts(hosts []string, ports string) []PortResult {
	var results []PortResult
	var resultMutex sync.Mutex

	// 解析端口
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口配置: " + ports)
		return results
	}

	Common.LogInfo(fmt.Sprintf("开始端口扫描: %d个主机, %d个端口", len(hosts), len(portList)))

	// 计算总任务数并初始化进度条
	totalTasks := len(hosts) * len(portList)
	if Common.ShowProgress && totalTasks > 10 {
		Common.ProgressBar = progressbar.NewOptions(totalTasks,
			progressbar.OptionSetDescription("端口扫描"),
			progressbar.OptionSetWidth(50),
			progressbar.OptionShowCount(),
			progressbar.OptionSetTheme(progressbar.Theme{Saucer: "=", SaucerPadding: "-", BarStart: "[", BarEnd: "]"}))
	}

	// 使用协程池控制并发
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskChan := make(chan PortScanTask, totalTasks)
	workerCount := Common.ThreadNum
	if workerCount > totalTasks {
		workerCount = totalTasks
	}

	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, taskChan, &results, &resultMutex)
		}()
	}

	// 生成扫描任务
	go func() {
		defer close(taskChan)
		for _, host := range hosts {
			for _, port := range portList {
				select {
				case taskChan <- PortScanTask{Host: host, Port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()

	if Common.ProgressBar != nil {
		Common.ProgressBar.Finish()
		fmt.Println()
	}

	Common.LogInfo(fmt.Sprintf("端口扫描完成，发现 %d 个开放端口", len(results)))
	return results
}

type PortScanTask struct {
	Host string
	Port int
}

// worker 扫描工作协程 - 学习gogo的处理方式
func (s *EnhancedPortScanner) worker(ctx context.Context, taskChan <-chan PortScanTask, results *[]PortResult, mutex *sync.Mutex) {
	for {
		select {
		case task, ok := <-taskChan:
			if !ok {
				return
			}

			// 应用智能速率控制
			Common.SmartWait()

			result := s.scanSinglePort(task.Host, task.Port)
			if result != nil {
				mutex.Lock()
				*results = append(*results, *result)
				mutex.Unlock()

				// 记录扫描结果
				s.logPortResult(result)
			}

			// 更新进度
			if Common.ProgressBar != nil {
				Common.ProgressBar.Add(1)
			}

		case <-ctx.Done():
			return
		}
	}
}

// scanSinglePort 扫描单个端口 - 核心逻辑学习gogo
func (s *EnhancedPortScanner) scanSinglePort(host string, port int) *PortResult {
	target := fmt.Sprintf("%s:%d", host, port)

	// 1. TCP连接测试
	conn, err := net.DialTimeout("tcp", target, s.timeout)
	if err != nil {
		return nil // 端口未开放
	}
	defer conn.Close()

	result := &PortResult{
		Host:     host,
		Port:     port,
		Status:   "open",
		Protocol: "tcp",
		Service:  "unknown",
		Headers:  make(map[string]string),
	}

	// 记录统计
	Common.PerfMonitor.RecordPacket(true)

	// 2. 尝试读取Banner - 学习gogo的方式
	banner := s.readBanner(conn)
	if banner != "" {
		result.Banner = banner
		result.Service = s.identifyServiceFromBanner(banner, port)
	}

	// 3. 如果没有Banner，尝试HTTP探测 - 学习gogo的自动探测
	if banner == "" || s.looksLikeHttp(banner, port) {
		s.probeHttp(result)
	}

	// 4. 进行通用TCP服务检测 - 学习gogo的全端口检测
	s.performUniversalTcpChecks(result)

	// 5. 检测常见未授权服务
	s.checkUnauthorizedServices(result)

	return result
}

// readBanner 读取服务Banner - 学习gogo的实现
func (s *EnhancedPortScanner) readBanner(conn net.Conn) string {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 先尝试直接读取Banner (某些服务会主动发送)
	buffer := make([]byte, s.maxBanner)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		return strings.TrimSpace(string(buffer[:n]))
	}

	// 如果没有Banner，尝试发送通用探测包
	return s.probeBannerWithRequests(conn)
}

// probeBannerWithRequests 通过发送特定请求获取Banner - 学习gogo的多协议探测
func (s *EnhancedPortScanner) probeBannerWithRequests(conn net.Conn) string {
	// 获取端口号用于智能探测
	addr := conn.RemoteAddr().String()
	port := 0
	if parts := strings.Split(addr, ":"); len(parts) == 2 {
		port, _ = strconv.Atoi(parts[1])
	}

	// 根据端口进行智能探测
	probes := s.getProbesForPort(port)

	for _, probe := range probes {
		// 设置写入超时
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		// 发送探测包
		_, err := conn.Write([]byte(probe.payload))
		if err != nil {
			continue
		}

		// 读取响应
		buffer := make([]byte, s.maxBanner)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			response := strings.TrimSpace(string(buffer[:n]))
			if response != "" {
				return response
			}
		}
	}

	return ""
}

// ProbeDefinition 探测包定义
type ProbeDefinition struct {
	name    string
	payload string
	ports   []int
}

// getProbesForPort 根据端口获取探测包 - 学习gogo的智能探测
func (s *EnhancedPortScanner) getProbesForPort(port int) []ProbeDefinition {
	// 通用探测包
	probes := []ProbeDefinition{
		// HTTP探测
		{
			name:    "HTTP",
			payload: "GET / HTTP/1.1\r\nHost: \r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
			ports:   []int{80, 8080, 8000, 8081, 8090, 8443, 443, 9000, 7001},
		},
		// HTTPS探测 (先发HTTP，如果失败再尝试TLS)
		{
			name:    "HTTPS",
			payload: "GET / HTTP/1.1\r\nHost: \r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
			ports:   []int{443, 8443, 9443, 8081},
		},
		// SSH探测
		{
			name:    "SSH",
			payload: "SSH-2.0-fscan\r\n",
			ports:   []int{22, 2222},
		},
		// FTP探测
		{
			name:    "FTP",
			payload: "USER anonymous\r\n",
			ports:   []int{21},
		},
		// SMTP探测
		{
			name:    "SMTP",
			payload: "EHLO fscan.local\r\n",
			ports:   []int{25, 587, 465},
		},
		// POP3探测
		{
			name:    "POP3",
			payload: "USER test\r\n",
			ports:   []int{110, 995},
		},
		// IMAP探测
		{
			name:    "IMAP",
			payload: "A001 CAPABILITY\r\n",
			ports:   []int{143, 993},
		},
		// Telnet探测
		{
			name:    "Telnet",
			payload: "\r\n",
			ports:   []int{23},
		},
		// 通用TCP探测 - 发送简单字符串
		{
			name:    "Generic",
			payload: "\r\n\r\n",
			ports:   []int{}, // 适用于所有端口
		},
	}

	// 筛选适用于当前端口的探测包
	var applicableProbes []ProbeDefinition

	for _, probe := range probes {
		// 如果探测包没有指定端口，则适用于所有端口
		if len(probe.ports) == 0 {
			applicableProbes = append(applicableProbes, probe)
			continue
		}

		// 检查端口是否匹配
		for _, p := range probe.ports {
			if p == port {
				applicableProbes = append(applicableProbes, probe)
				break
			}
		}
	}

	// 如果没有特定探测包，至少返回通用探测
	if len(applicableProbes) == 0 {
		applicableProbes = append(applicableProbes, ProbeDefinition{
			name:    "Generic",
			payload: "\r\n",
			ports:   []int{},
		})
	}

	return applicableProbes
}

// performUniversalTcpChecks 对所有TCP端口进行通用检测 - 学习gogo的全面检测
func (s *EnhancedPortScanner) performUniversalTcpChecks(result *PortResult) {
	// 基于服务类型进行特定检测
	switch result.Service {
	case "ssh":
		s.checkSSHService(result)
	case "ftp":
		s.checkFTPService(result)
	case "mysql":
		s.checkMySQLService(result)
	case "redis":
		s.checkRedisService(result)
	case "mongodb":
		s.checkMongoService(result)
	case "postgresql":
		s.checkPostgreSQLService(result)
	case "elasticsearch":
		s.checkElasticsearchService(result)
	case "memcached":
		s.checkMemcachedService(result)
	case "oracle":
		s.checkOracleService(result)
	case "mssql":
		s.checkMSSQLService(result)
	case "ldap":
		s.checkLDAPService(result)
	case "vnc":
		s.checkVNCService(result)
	case "rdp":
		s.checkRDPService(result)
	case "smb", "microsoft-ds", "netbios-ssn":
		s.checkSMBService(result)
	case "jdwp":
		s.checkJDWPService(result)
	case "docker":
		s.checkDockerService(result)
	case "tcp-banner", "tcp-unknown":
		s.checkUnknownTcpService(result)
	}
}

// checkSSHService SSH服务检测
func (s *EnhancedPortScanner) checkSSHService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "openssh") {
		// 检查SSH版本信息
		if strings.Contains(result.Banner, "OpenSSH_") {
			result.Headers["ssh_version"] = result.Banner
		}
	}
}

// checkFTPService FTP服务检测
func (s *EnhancedPortScanner) checkFTPService(result *PortResult) {
	// 检查匿名FTP
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), s.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// 尝试匿名登录
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err == nil {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "230") || strings.Contains(response, "331") {
				result.Vulns = append(result.Vulns, "FTP匿名登录")
			}
		}
	}
}

// checkMySQLService MySQL服务检测
func (s *EnhancedPortScanner) checkMySQLService(result *PortResult) {
	// 从Banner中提取版本信息
	if strings.Contains(strings.ToLower(result.Banner), "mysql") {
		result.Headers["mysql_banner"] = result.Banner
	}
}

// checkRedisService Redis服务检测
func (s *EnhancedPortScanner) checkRedisService(result *PortResult) {
	// 尝试INFO命令检测未授权访问
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), s.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	_, err = conn.Write([]byte("INFO\r\n"))
	if err == nil {
		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "redis_version") {
				result.Vulns = append(result.Vulns, "Redis未授权访问")
				result.Headers["redis_info"] = response[:min(200, len(response))]
			}
		}
	}
}

// checkMongoService MongoDB服务检测
func (s *EnhancedPortScanner) checkMongoService(result *PortResult) {
	// 检测MongoDB未授权访问
	if strings.Contains(strings.ToLower(result.Banner), "mongodb") {
		result.Headers["mongodb_banner"] = result.Banner
	}
}

// checkPostgreSQLService PostgreSQL服务检测
func (s *EnhancedPortScanner) checkPostgreSQLService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "postgres") {
		result.Headers["postgresql_banner"] = result.Banner
	}
}

// checkElasticsearchService Elasticsearch服务检测
func (s *EnhancedPortScanner) checkElasticsearchService(result *PortResult) {
	// ES通常在9200端口，尝试HTTP请求
	url := fmt.Sprintf("http://%s:%d/", result.Host, result.Port)
	client := &http.Client{Timeout: s.httpTimeout}

	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			result.Vulns = append(result.Vulns, "Elasticsearch未授权访问")
		}
	}
}

// checkMemcachedService Memcached服务检测
func (s *EnhancedPortScanner) checkMemcachedService(result *PortResult) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), s.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	_, err = conn.Write([]byte("stats\r\n"))
	if err == nil {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			response := string(buffer[:n])
			if strings.Contains(response, "STAT") {
				result.Vulns = append(result.Vulns, "Memcached未授权访问")
			}
		}
	}
}

// checkOracleService Oracle服务检测
func (s *EnhancedPortScanner) checkOracleService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "oracle") || strings.Contains(strings.ToLower(result.Banner), "tns") {
		result.Headers["oracle_banner"] = result.Banner
	}
}

// checkMSSQLService MSSQL服务检测
func (s *EnhancedPortScanner) checkMSSQLService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "sql server") {
		result.Headers["mssql_banner"] = result.Banner
	}
}

// checkLDAPService LDAP服务检测
func (s *EnhancedPortScanner) checkLDAPService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "ldap") {
		result.Headers["ldap_banner"] = result.Banner
	}
}

// checkVNCService VNC服务检测
func (s *EnhancedPortScanner) checkVNCService(result *PortResult) {
	if strings.Contains(strings.ToLower(result.Banner), "rfb") {
		result.Headers["vnc_banner"] = result.Banner
		// VNC可能无密码
		if strings.Contains(result.Banner, "003.008") {
			result.Vulns = append(result.Vulns, "VNC可能无密码")
		}
	}
}

// checkRDPService RDP服务检测
func (s *EnhancedPortScanner) checkRDPService(result *PortResult) {
	if result.Port == 3389 {
		result.Headers["rdp_detected"] = "true"
	}
}

// checkSMBService SMB服务检测
func (s *EnhancedPortScanner) checkSMBService(result *PortResult) {
	if result.Port == 445 || result.Port == 139 {
		result.Headers["smb_detected"] = "true"
	}
}

// checkJDWPService JDWP服务检测 - 特别检测
func (s *EnhancedPortScanner) checkJDWPService(result *PortResult) {
	// 对于JDWP端口进行详细检测
	// JDWP协议握手包
	handshakeRequest := []byte("JDWP-Handshake")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// 发送JDWP握手包
	_, err = conn.Write(handshakeRequest)
	if err != nil {
		return
	}

	// 读取响应
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return
	}

	// 检查是否返回JDWP握手响应
	if string(response[:n]) == "JDWP-Handshake" {
		result.Vulns = append(result.Vulns, "JDWP Java调试协议未授权访问")
		result.Headers["jdwp_handshake"] = "success"

		// 尝试发送Version命令获取更多信息
		versionCmd := []byte{0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01}
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		_, err = conn.Write(versionCmd)
		if err == nil {
			versionResp := make([]byte, 512)
			n, err := conn.Read(versionResp)
			if err == nil && n > 11 {
				// 检查响应是否是JDWP格式
				if len(versionResp) >= 11 && versionResp[8] == 0x80 {
					result.Headers["jdwp_version_response"] = "received"
					// 可以进一步解析JVM版本信息
				}
			}
		}
	}
}

// checkDockerService Docker服务检测
func (s *EnhancedPortScanner) checkDockerService(result *PortResult) {
	if result.Port == 2375 || result.Port == 2376 {
		s.checkDockerAPI(result)
	}
}

// checkUnknownTcpService 未知TCP服务检测
func (s *EnhancedPortScanner) checkUnknownTcpService(result *PortResult) {
	// 对于未知服务，尝试更多探测
	if result.Banner != "" {
		bannerLower := strings.ToLower(result.Banner)

		// 检查是否可能是HTTP服务
		if strings.Contains(bannerLower, "http") || strings.Contains(bannerLower, "server") {
			result.Service = "http-like"
			s.probeHttp(result)
		}

		// 检查是否包含版本信息
		if strings.Contains(bannerLower, "version") {
			result.Headers["version_info"] = result.Banner
		}
	}
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// looksLikeHttp 判断是否可能是HTTP服务
func (s *EnhancedPortScanner) looksLikeHttp(banner string, port int) bool {
	// 检查常见HTTP端口
	httpPorts := []int{80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}

	// 检查Banner特征
	httpIndicators := []string{"HTTP/", "html", "HTTP", "Server:", "Content-"}
	bannerLower := strings.ToLower(banner)
	for _, indicator := range httpIndicators {
		if strings.Contains(bannerLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// probeHttp HTTP探测 - 学习gogo的协议自动识别
func (s *EnhancedPortScanner) probeHttp(result *PortResult) {
	// 尝试HTTPS
	if s.tryHttpRequest(result, "https") {
		result.Protocol = "https"
		return
	}

	// 尝试HTTP
	if s.tryHttpRequest(result, "http") {
		result.Protocol = "http"
		return
	}
}

// tryHttpRequest 尝试HTTP请求
func (s *EnhancedPortScanner) tryHttpRequest(result *PortResult, scheme string) bool {
	url := fmt.Sprintf("%s://%s:%d/", scheme, result.Host, result.Port)

	client := &http.Client{
		Timeout: s.httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: s.timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "fscan/2.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 成功获取HTTP响应
	result.Service = scheme
	result.Headers["status"] = strconv.Itoa(resp.StatusCode)
	result.Headers["server"] = resp.Header.Get("Server")

	// 读取标题
	if resp.StatusCode < 400 {
		title := s.extractTitle(resp)
		if title != "" {
			result.Title = title
		}
	}

	return true
}

// extractTitle 提取网页标题
func (s *EnhancedPortScanner) extractTitle(resp *http.Response) string {
	scanner := bufio.NewScanner(resp.Body)
	var content strings.Builder
	lineCount := 0

	for scanner.Scan() && lineCount < 20 { // 只读前20行
		content.WriteString(scanner.Text())
		lineCount++
	}

	titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(content.String())
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if len(title) > 100 {
			title = title[:100] + "..."
		}
		return title
	}

	return ""
}

// identifyServiceFromBanner 从Banner识别服务 - 增强版类似gogo的识别能力
func (s *EnhancedPortScanner) identifyServiceFromBanner(banner string, port int) string {
	bannerLower := strings.ToLower(banner)

	// 扩展的服务特征匹配 - 学习gogo的指纹库
	services := map[string][]string{
		"ssh":           {"ssh", "openssh", "ssh-2.0"},
		"ftp":           {"ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla", "220"},
		"smtp":          {"smtp", "postfix", "sendmail", "exim", "220", "mail"},
		"http":          {"http/", "server:", "apache", "nginx", "iis", "lighttpd", "tomcat"},
		"mysql":         {"mysql", "mariadb", "5.7.", "5.6.", "8.0."},
		"redis":         {"redis", "-redis", "+pong"},
		"mongodb":       {"mongodb", "mongo", "dbversion"},
		"postgresql":    {"postgresql", "postgres", "ready for connections"},
		"telnet":        {"telnet", "login:", "username:", "welcome"},
		"pop3":          {"pop3", "+ok", "ready"},
		"imap":          {"imap", "* ok", "ready"},
		"dns":           {"bind", "dns", "version"},
		"ldap":          {"ldap", "ldaps", "directory"},
		"vnc":           {"vnc", "rfb", "remote framebuffer"},
		"rdp":           {"rdp", "terminal services"},
		"snmp":          {"snmp", "v1", "v2c", "v3"},
		"ntp":           {"ntp", "stratum"},
		"sip":           {"sip", "100 trying", "200 ok"},
		"rtsp":          {"rtsp", "200 ok", "server: "},
		"ajp":           {"ajp13", "ajp/"},
		"elasticsearch": {"elasticsearch", "cluster_name", "lucene"},
		"memcached":     {"memcached", "version"},
		"cassandra":     {"cassandra", "cql"},
		"oracle":        {"oracle", "tns", "listener"},
		"mssql":         {"microsoft sql server", "mssql"},
		"smb":           {"smb", "cifs", "workgroup"},
		"netbios":       {"netbios", "workstation", "domain"},
		"kerberos":      {"kerberos", "krb5"},
		"jdwp":          {"jdwp-handshake", "java", "jvm"},
		"docker":        {"docker", "registry", "distribution"},
		"kubernetes":    {"kubernetes", "k8s"},
		"etcd":          {"etcd", "raft"},
		"consul":        {"consul", "raft"},
		"zookeeper":     {"zookeeper", "kafka", "broker"},
		"activemq":      {"activemq", "openwire"},
		"rabbitmq":      {"rabbitmq", "amqp"},
		"neo4j":         {"neo4j", "graph"},
	}

	// 首先基于Banner内容匹配
	for service, patterns := range services {
		for _, pattern := range patterns {
			if strings.Contains(bannerLower, pattern) {
				return service
			}
		}
	}

	// 扩展的端口服务映射 - 包含更多常见服务
	portServices := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		161:   "snmp",
		389:   "ldap",
		443:   "https",
		445:   "microsoft-ds",
		465:   "smtps",
		514:   "syslog",
		515:   "printer",
		548:   "afp",
		587:   "submission",
		636:   "ldaps",
		993:   "imaps",
		995:   "pop3s",
		1080:  "socks",
		1099:  "rmiregistry",
		1433:  "mssql",
		1521:  "oracle",
		1723:  "pptp",
		2049:  "nfs",
		2181:  "zookeeper",
		2375:  "docker",
		2376:  "docker-ssl",
		3268:  "ldap-gc",
		3269:  "ldap-gc-ssl",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5555:  "freeciv",
		5672:  "amqp",
		5900:  "vnc",
		6379:  "redis",
		6667:  "irc",
		7000:  "cassandra",
		7001:  "afs3-callback",
		8000:  "http-alt",
		8080:  "http-proxy",
		8081:  "http-alt",
		8443:  "https-alt",
		9000:  "cslistener",
		9042:  "cassandra-cql",
		9200:  "elasticsearch",
		9300:  "elasticsearch",
		11211: "memcached",
		27017: "mongodb",
		27018: "mongodb",
		50070: "hadoop",
	}

	if service, exists := portServices[port]; exists {
		return service
	}

	// 如果有Banner但无法识别，标记为tcp-banner
	if banner != "" {
		return "tcp-banner"
	}

	return "tcp-unknown"
}

// checkUnauthorizedServices 检测常见未授权服务
func (s *EnhancedPortScanner) checkUnauthorizedServices(result *PortResult) {
	switch result.Port {
	case 2375, 2376: // Docker API
		s.checkDockerAPI(result)
	case 8080, 8081, 8090: // 各种Web服务
		s.checkCommonWebVulns(result)
	case 5984, 5985: // CouchDB
		s.checkCouchDB(result)
	case 9200, 9300: // Elasticsearch
		s.checkElasticsearch(result)
	case 6379: // Redis
		s.checkRedisUnauth(result)
	case 11211: // Memcached
		s.checkMemcached(result)
	case 27017, 27018: // MongoDB
		s.checkMongoDB(result)
	case 3000: // 可能是Grafana等
		s.checkWebServices(result)
	case 5005, 8000, 8787, 9999, 18000: // JDWP端口主动检测
		s.performJDWPCheck(result)
	}
}

// performJDWPCheck 主动进行JDWP检测 - 确保识别所有JDWP端口
func (s *EnhancedPortScanner) performJDWPCheck(result *PortResult) {
	Common.LogDebug(fmt.Sprintf("主动检测JDWP端口: %s:%d", result.Host, result.Port))

	// JDWP协议握手包
	handshakeRequest := []byte("JDWP-Handshake")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 发送JDWP握手包
	_, err = conn.Write(handshakeRequest)
	if err != nil {
		return
	}

	// 读取响应
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil || n == 0 {
		return
	}

	// 检查是否返回JDWP握手响应
	if string(response[:n]) == "JDWP-Handshake" {
		result.Service = "jdwp"
		result.Banner = "JDWP-Handshake"
		result.Vulns = append(result.Vulns, "JDWP Java调试协议未授权访问")
		result.Headers["jdwp_handshake"] = "success"

		Common.LogError(fmt.Sprintf("发现JDWP未授权访问: %s:%d", result.Host, result.Port))

		// 尝试发送Version命令获取更多信息
		versionCmd := []byte{0x00, 0x0B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01}
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		_, err = conn.Write(versionCmd)
		if err == nil {
			versionResp := make([]byte, 512)
			n, err := conn.Read(versionResp)
			if err == nil && n > 11 {
				// 检查响应是否是JDWP格式
				if len(versionResp) >= 11 && versionResp[8] == 0x80 {
					result.Headers["jdwp_version_response"] = "received"
					// 解析JVM版本信息
					if n > 20 {
						result.Headers["jdwp_extra_info"] = "version_available"
					}
				}
			}
		}
	}
}

// checkDockerAPI 检测Docker API未授权
func (s *EnhancedPortScanner) checkDockerAPI(result *PortResult) {
	url := fmt.Sprintf("http://%s:%d/version", result.Host, result.Port)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Service = "docker-api"
		result.Vulns = append(result.Vulns, "Docker API未授权访问")
		Common.LogError(fmt.Sprintf("发现Docker API未授权: %s:%d", result.Host, result.Port))
	}
}

// checkCommonWebVulns 检测常见Web服务漏洞
func (s *EnhancedPortScanner) checkCommonWebVulns(result *PortResult) {
	vulnChecks := []struct {
		path    string
		keyword string
		vuln    string
	}{
		{"/actuator/health", "status", "Spring Boot Actuator未授权"},
		{"/management/health", "status", "Spring Boot Management未授权"},
		{"/api/v1/namespaces", "items", "Kubernetes API未授权"},
		{"/jolokia/", "jolokia", "Jolokia未授权访问"},
		{"/druid/index.html", "druid", "Druid监控页面未授权"},
		{"/console", "console", "Web控制台未授权"},
	}

	for _, check := range vulnChecks {
		if s.checkHttpPath(result.Host, result.Port, check.path, check.keyword) {
			result.Vulns = append(result.Vulns, check.vuln)
		}
	}
}

// checkHttpPath 检测HTTP路径
func (s *EnhancedPortScanner) checkHttpPath(host string, port int, path, keyword string) bool {
	url := fmt.Sprintf("http://%s:%d%s", host, port, path)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if strings.Contains(strings.ToLower(scanner.Text()), strings.ToLower(keyword)) {
				return true
			}
		}
	}

	return false
}

// checkElasticsearch 检测Elasticsearch未授权
func (s *EnhancedPortScanner) checkElasticsearch(result *PortResult) {
	if s.checkHttpPath(result.Host, result.Port, "/", "cluster_name") {
		result.Service = "elasticsearch"
		result.Vulns = append(result.Vulns, "Elasticsearch未授权访问")
	}
}

// checkRedisUnauth 检测Redis未授权
func (s *EnhancedPortScanner) checkRedisUnauth(result *PortResult) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 发送Redis INFO命令
	conn.Write([]byte("INFO\r\n"))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return
	}

	response := string(buffer[:n])
	if strings.Contains(response, "redis_version") {
		result.Service = "redis"
		result.Vulns = append(result.Vulns, "Redis未授权访问")
	}
}

// checkMongoDB 检测MongoDB未授权
func (s *EnhancedPortScanner) checkMongoDB(result *PortResult) {
	// 简单的MongoDB连接测试
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// MongoDB wire protocol很复杂，这里简化处理
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		result.Service = "mongodb"
		// 实际检测需要更复杂的协议交互
	}
}

// checkMemcached 检测Memcached未授权
func (s *EnhancedPortScanner) checkMemcached(result *PortResult) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", result.Host, result.Port), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 发送stats命令
	conn.Write([]byte("stats\r\n"))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return
	}

	response := string(buffer[:n])
	if strings.Contains(response, "STAT") {
		result.Service = "memcached"
		result.Vulns = append(result.Vulns, "Memcached未授权访问")
	}
}

// checkCouchDB 检测CouchDB未授权
func (s *EnhancedPortScanner) checkCouchDB(result *PortResult) {
	if s.checkHttpPath(result.Host, result.Port, "/", "couchdb") {
		result.Service = "couchdb"
		result.Vulns = append(result.Vulns, "CouchDB未授权访问")
	}
}

// checkWebServices 检测Web服务
func (s *EnhancedPortScanner) checkWebServices(result *PortResult) {
	webServices := []struct {
		path    string
		keyword string
		service string
		vuln    string
	}{
		{"/", "grafana", "grafana", "Grafana默认配置"},
		{"/", "jenkins", "jenkins", "Jenkins未授权访问"},
		{"/phpmyadmin/", "phpMyAdmin", "phpmyadmin", "phpMyAdmin暴露"},
		{"/adminer/", "adminer", "adminer", "Adminer暴露"},
	}

	for _, check := range webServices {
		if s.checkHttpPath(result.Host, result.Port, check.path, check.keyword) {
			result.Service = check.service
			if check.vuln != "" {
				result.Vulns = append(result.Vulns, check.vuln)
			}
		}
	}
}

// logPortResult 记录端口扫描结果
func (s *EnhancedPortScanner) logPortResult(result *PortResult) {
	// 保存到结果系统
	details := map[string]interface{}{
		"port":     result.Port,
		"protocol": result.Protocol,
		"service":  result.Service,
	}

	if result.Banner != "" {
		details["banner"] = result.Banner
	}

	if result.Title != "" {
		details["title"] = result.Title
	}

	if len(result.Headers) > 0 {
		details["headers"] = result.Headers
	}

	if len(result.Vulns) > 0 {
		details["vulns"] = result.Vulns
	}

	scanResult := &Common.ScanResult{
		Time:    time.Now(),
		Type:    Common.PORT,
		Target:  result.Host,
		Status:  result.Status,
		Details: details,
	}

	Common.SaveResult(scanResult)

	// 简单输出 - 恢复原始方式
	addr := fmt.Sprintf("%s:%d", result.Host, result.Port)
	if len(result.Vulns) > 0 {
		// 有漏洞立即显示
		Common.LogError(fmt.Sprintf("端口开放 %s [%s] 存在漏洞: %s", addr, result.Service, strings.Join(result.Vulns, ", ")))
	} else if result.Banner != "" {
		// 有Banner信息
		Common.LogInfo(fmt.Sprintf("端口开放 %s [%s] Banner: %s", addr, result.Service, result.Banner))
	} else {
		// 普通端口
		Common.LogInfo(fmt.Sprintf("端口开放 %s [%s]", addr, result.Service))
	}
}

// NewEnhancedPortScan 新的增强端口扫描函数
func NewEnhancedPortScan(hosts []string, ports string, timeout int64) []string {
	scanner := NewEnhancedPortScanner()
	results := scanner.ScanPorts(hosts, ports)

	// 转换为原有格式的地址列表
	var addresses []string
	for _, result := range results {
		addresses = append(addresses, fmt.Sprintf("%s:%d", result.Host, result.Port))
	}

	return addresses
}
