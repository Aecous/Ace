package Core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// EnhancedPortScan 高性能端口扫描函数
func EnhancedPortScan(hosts []string, ports string, timeout int64) []string {
	// 解析端口和排除端口
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口: " + ports)
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	// 初始化并发控制
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	to := time.Duration(timeout) * time.Second
	sem := semaphore.NewWeighted(int64(Common.ThreadNum))
	var count int64
	var aliveMap sync.Map
	g, ctx := errgroup.WithContext(ctx)

	// 并发扫描所有目标
	for _, host := range hosts {
		for _, port := range portList {
			if _, excluded := exclude[port]; excluded {
				continue
			}

			host, port := host, port // 捕获循环变量
			addr := fmt.Sprintf("%s:%d", host, port)

			if err := sem.Acquire(ctx, 1); err != nil {
				break
			}

			g.Go(func() error {
				defer sem.Release(1)

				// 连接测试
				conn, err := net.DialTimeout("tcp", addr, to)
				if err != nil {
					return nil
				}

				// 记录开放端口
				atomic.AddInt64(&count, 1)
				aliveMap.Store(addr, struct{}{})

				// 优化的Gogo风格服务指纹识别 - 复用连接避免重复
				var result *GogoFingerResult
				if Common.EnableFingerprint {
					result = OptimizedIdentifyService(host, port, conn, to)
				}

				// 关闭连接
				conn.Close()

				if result != nil {
					// 优化：根据识别结果使用正确的协议前缀（学习gogo）
					protocol := result.Protocol
					if protocol == "" {
						protocol = "tcp" // 默认值
					}

					// 构建结果详情
					details := map[string]interface{}{
						"port":       port,
						"service":    result.Service,
						"confidence": result.Confidence,
						"type":       result.FingerType,
						"protocol":   protocol, // 添加协议信息
					}

					if result.Product != "" {
						details["product"] = result.Product
					}
					if result.Version != "" {
						details["version"] = result.Version
					}
					if result.Banner != "" {
						details["banner"] = strings.TrimSpace(result.Banner)
					}
					for k, v := range result.ExtraInfo {
						if v != "" {
							details[k] = v
						}
					}

					// 保存服务结果
					Common.SaveResult(&Common.ScanResult{
						Time: time.Now(), Type: Common.SERVICE, Target: host,
						Status: "identified", Details: details,
					})

					// 记录服务信息 - 使用gogo风格的格式化输出，协议前缀正确
					serviceInfo := result.FormatResult()
					if serviceInfo != "" {
						Common.LogInfo(fmt.Sprintf("服务识别 %s://%s => %s", protocol, addr, serviceInfo))
					}
				} else {
					// 没有识别到服务，但端口开放
					Common.LogInfo(fmt.Sprintf("端口开放 %s", addr))
				}

				return nil
			})
		}
	}

	_ = g.Wait()

	// 收集结果
	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogBase(fmt.Sprintf("扫描完成, 发现 %d 个开放端口", count))
	return aliveAddrs
}

// FastPortScanWithBanner 快速端口扫描+Banner检测 - 学习gogo的高效方式
func FastPortScanWithBanner(hosts []string, ports string, timeout int64) []string {
	// 解析端口和排除端口
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口: " + ports)
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	// 初始化并发控制
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	to := time.Duration(timeout) * time.Second
	sem := semaphore.NewWeighted(int64(Common.ThreadNum))
	var count int64
	var aliveMap sync.Map
	g, ctx := errgroup.WithContext(ctx)

	// 并发扫描所有目标
	for _, host := range hosts {
		for _, port := range portList {
			if _, excluded := exclude[port]; excluded {
				continue
			}

			host, port := host, port // 捕获循环变量
			addr := fmt.Sprintf("%s:%d", host, port)

			if err := sem.Acquire(ctx, 1); err != nil {
				break
			}

			g.Go(func() error {
				defer sem.Release(1)

				// 应用端口扫描专用的轻量级速率控制
				Common.PortScanWait()

				// 记录开放端口和成功的网络连接
				atomic.AddInt64(&count, 1)
				aliveMap.Store(addr, struct{}{})
				Common.PerfMonitor.RecordPacket(true)

				// 🚀 使用动态协议扫描 - 学习gogo/fscanx的自动协议识别
				var result *GogoFingerResult

				if Common.EnableFingerprint {
					// 检查是否启用动态协议识别
					if Common.EnableDynamicProtocol {
						Common.LogDebug(fmt.Sprintf("启用动态协议识别: %s", addr))
						// 动态协议扫描：无需预设HTTP端口，自动识别协议
						dynamicStart := time.Now()
						dynamicResult := FastDynamicScan(host, port)
						dynamicTime := time.Since(dynamicStart)

						if dynamicResult != nil && dynamicResult.Open {
							Common.LogDebug(fmt.Sprintf("动态协议识别成功: %s - 协议: %s, HTTP: %v (耗时: %v)",
								addr, dynamicResult.Protocol, dynamicResult.IsHttp, dynamicTime))

							// 转换为GogoFingerResult格式保持兼容性
							result = &GogoFingerResult{
								Service:    dynamicResult.Protocol,
								Product:    "", // 可在后续版本中加入产品识别
								Protocol:   dynamicResult.Protocol,
								Port:       port,
								Banner:     string(dynamicResult.Banner),
								Confidence: 8,
								ExtraInfo: map[string]string{
									"status": dynamicResult.Status,
								},
								FingerType: "dynamic",
							}

							// HTTP特有信息
							if dynamicResult.IsHttp {
								result.Service = "http"
								result.FingerType = "http"
								result.ExtraInfo["title"] = dynamicResult.Title
								result.ExtraInfo["server"] = dynamicResult.Server
								result.ExtraInfo["status_code"] = dynamicResult.Status
								Common.LogDebug(fmt.Sprintf("HTTP服务详情: %s - 标题: %s, 服务器: %s, 状态: %s",
									addr, dynamicResult.Title, dynamicResult.Server, dynamicResult.Status))
							}
						} else {
							Common.LogDebug(fmt.Sprintf("动态协议识别无结果: %s (耗时: %v)", addr, dynamicTime))
						}
					} else {
						Common.LogDebug(fmt.Sprintf("动态协议识别已禁用: %s", addr))
					}

					// 如果动态扫描失败或未启用，回退到传统方式
					if result == nil {
						Common.LogDebug(fmt.Sprintf("回退到传统指纹识别: %s", addr))
						// 建立连接进行传统指纹识别
						conn, err := net.DialTimeout("tcp", addr, to)
						if err != nil {
							Common.LogDebug(fmt.Sprintf("传统指纹识别连接失败: %s - %v", addr, err))
							Common.PerfMonitor.RecordPacket(true)
							return nil
						}
						traditionalStart := time.Now()
						result = OptimizedIdentifyService(host, port, conn, to)
						traditionalTime := time.Since(traditionalStart)
						conn.Close()

						if result != nil {
							Common.LogDebug(fmt.Sprintf("传统指纹识别成功: %s - 服务: %s (耗时: %v)",
								addr, result.Service, traditionalTime))
						} else {
							Common.LogDebug(fmt.Sprintf("传统指纹识别无结果: %s (耗时: %v)", addr, traditionalTime))
						}
					}
				} else {
					Common.LogDebug(fmt.Sprintf("指纹识别已禁用，仅进行连接测试: %s", addr))
					// 未启用指纹识别，只进行简单连接测试
					conn, err := net.DialTimeout("tcp", addr, to)
					if err != nil {
						Common.LogDebug(fmt.Sprintf("简单连接测试失败: %s - %v", addr, err))
						Common.PerfMonitor.RecordPacket(true)
						return nil
					}
					conn.Close()
					Common.LogDebug(fmt.Sprintf("简单连接测试成功: %s", addr))
				}

				if Common.EnableFingerprint {
					if result != nil {
						// 优化：根据识别结果使用正确的协议前缀（学习gogo）
						protocol := result.Protocol
						if protocol == "" {
							protocol = "tcp" // 默认值
						}

						// gogo风格输出: [+] protocol://host:port  focus:service:status  [open] response [ info: ... ]
						serviceInfo := result.FormatResult()
						Common.LogInfo(fmt.Sprintf("[+] %s://%s  %s", protocol, addr, serviceInfo))

						// 构建详细结果数据
						details := map[string]interface{}{
							"port":       port,
							"service":    result.Service,
							"confidence": result.Confidence,
							"type":       result.FingerType,
							"protocol":   protocol, // 添加协议信息
						}

						if result.Product != "" {
							details["product"] = result.Product
						}
						if result.Version != "" {
							details["version"] = result.Version
						}
						if result.Banner != "" {
							details["banner"] = strings.TrimSpace(result.Banner)
						}
						for k, v := range result.ExtraInfo {
							if v != "" {
								details[k] = v
							}
						}

						// 保存服务结果
						Common.SaveResult(&Common.ScanResult{
							Time: time.Now(), Type: Common.SERVICE, Target: host,
							Status: "identified", Details: details,
						})
					} else {
						// 没有识别到服务，但端口开放 - 类似gogo的简单输出
						Common.LogInfo(fmt.Sprintf("[+] tcp://%s  [open]", addr))
					}
				} else {
					// 未启用指纹识别时的基础输出
					Common.LogInfo(fmt.Sprintf("[+] tcp://%s  [open]", addr))
				}

				// 基础端口记录（保持原有功能）
				Common.SaveResult(&Common.ScanResult{
					Time: time.Now(), Type: Common.PORT, Target: host,
					Status: "open", Details: map[string]interface{}{"port": port},
				})

				return nil
			})
		}
	}

	_ = g.Wait()

	// 收集结果
	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogBase(fmt.Sprintf("快速扫描完成, 发现 %d 个开放端口", count))
	return aliveAddrs
}

// GogoStylePortScan gogo风格的端口喷洒扫描 - 按端口批量扫描提升性能
func GogoStylePortScan(hosts []string, ports string, timeout int64) []string {
	// 解析端口和排除端口
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口: " + ports)
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	// 初始化超时设置
	to := time.Duration(timeout) * time.Second

	// 使用更大的线程池（学习gogo）
	threadNum := Common.ThreadNum
	if threadNum < 100 {
		threadNum = 100 // gogo默认使用较大的线程池
	}

	var count int64
	var aliveMap sync.Map

	// 按端口批量扫描（gogo的端口喷洒策略）
	Common.LogInfo("使用gogo风格端口喷洒模式扫描...")

	for _, port := range portList {
		if _, excluded := exclude[port]; excluded {
			continue
		}

		// 为每个端口创建独立的扫描批次
		portStartTime := time.Now()
		portCount := scanSinglePortBatch(hosts, port, to, &aliveMap, &count, threadNum)

		if portCount > 0 {
			elapsed := time.Since(portStartTime)
			Common.LogInfo(fmt.Sprintf("端口 %d 扫描完成，发现 %d 个开放服务，耗时 %v",
				port, portCount, elapsed))
		}
	}

	// 收集结果
	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogBase(fmt.Sprintf("gogo风格扫描完成, 发现 %d 个开放端口", count))
	return aliveAddrs
}

// scanSinglePortBatch 批量扫描单个端口的所有主机
func scanSinglePortBatch(hosts []string, port int, timeout time.Duration,
	aliveMap *sync.Map, totalCount *int64, threadNum int) int64 {

	var portCount int64
	var wg sync.WaitGroup

	// 创建任务通道（学习gogo的channel分发）
	taskCh := make(chan string, threadNum*2)

	// 启动工作协程池
	for i := 0; i < threadNum; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range taskCh {
				if scanPortWithOptimization(host, port, timeout, aliveMap, &portCount) {
					atomic.AddInt64(totalCount, 1)
				}
			}
		}()
	}

	// 分发任务
	go func() {
		for _, host := range hosts {
			taskCh <- host
		}
		close(taskCh)
	}()

	wg.Wait()
	return portCount
}

// scanPortWithOptimization 优化的单端口扫描
func scanPortWithOptimization(host string, port int, timeout time.Duration,
	aliveMap *sync.Map, portCount *int64) bool {

	addr := fmt.Sprintf("%s:%d", host, port)
	Common.LogDebug(fmt.Sprintf("开始扫描端口: %s (超时: %v)", addr, timeout))

	// 1. TCP连接测试
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	connectTime := time.Since(startTime)

	if err != nil {
		Common.LogDebug(fmt.Sprintf("端口连接失败: %s - %v (耗时: %v)", addr, err, connectTime))
		return false
	}

	Common.LogDebug(fmt.Sprintf("端口连接成功: %s (耗时: %v)", addr, connectTime))

	// 记录开放端口
	atomic.AddInt64(portCount, 1)
	aliveMap.Store(addr, struct{}{})

	// 2. 快速服务识别（复用连接）
	var result *GogoFingerResult
	if Common.EnableFingerprint {
		Common.LogDebug(fmt.Sprintf("开始服务指纹识别: %s", addr))
		fingerprintStart := time.Now()
		result = OptimizedIdentifyService(host, port, conn, timeout)
		fingerprintTime := time.Since(fingerprintStart)

		if result != nil {
			Common.LogDebug(fmt.Sprintf("指纹识别成功: %s - 服务: %s, 协议: %s, 置信度: %d (耗时: %v)",
				addr, result.Service, result.Protocol, result.Confidence, fingerprintTime))
		} else {
			Common.LogDebug(fmt.Sprintf("指纹识别无结果: %s (耗时: %v)", addr, fingerprintTime))
		}
	} else {
		Common.LogDebug(fmt.Sprintf("跳过指纹识别: %s (指纹识别已禁用)", addr))
	}

	// 关闭连接
	conn.Close()
	Common.LogDebug(fmt.Sprintf("连接已关闭: %s", addr))

	// 3. 输出结果
	if Common.EnableFingerprint && result != nil {
		protocol := result.Protocol
		if protocol == "" {
			protocol = "tcp"
		}

		serviceInfo := result.FormatResult()
		Common.LogInfo(fmt.Sprintf("[+] %s://%s  %s", protocol, addr, serviceInfo))
		Common.LogDebug(fmt.Sprintf("服务结果格式化完成: %s - %s", addr, serviceInfo))

		// 保存详细结果
		details := map[string]interface{}{
			"port":       port,
			"service":    result.Service,
			"confidence": result.Confidence,
			"type":       result.FingerType,
			"protocol":   protocol,
		}

		if result.Product != "" {
			details["product"] = result.Product
		}
		if result.Version != "" {
			details["version"] = result.Version
		}
		if result.Banner != "" {
			details["banner"] = strings.TrimSpace(result.Banner)
		}
		for k, v := range result.ExtraInfo {
			if v != "" {
				details[k] = v
			}
		}

		Common.SaveResult(&Common.ScanResult{
			Time: time.Now(), Type: Common.SERVICE, Target: host,
			Status: "identified", Details: details,
		})
		Common.LogDebug(fmt.Sprintf("服务结果已保存: %s", addr))
	} else {
		Common.LogInfo(fmt.Sprintf("[+] tcp://%s  [open]", addr))
		Common.LogDebug(fmt.Sprintf("基础端口结果输出: %s (无指纹信息)", addr))
	}

	totalTime := time.Since(startTime)
	Common.LogDebug(fmt.Sprintf("端口扫描完成: %s (总耗时: %v)", addr, totalTime))
	return true
}

// performProtocolProbing 执行协议探测 - 已被gogo风格指纹识别替代
// 此函数保留用于向后兼容，但建议使用 IdentifyService
func performProtocolProbing(host string, port int) (string, string) {
	// 使用新的gogo风格指纹识别
	if result := IdentifyService(host, port, 5*time.Second); result != nil {
		return result.Banner, result.Service
	}
	return "", "unknown"
}

// isJDWPPort 检查是否为JDWP端口
func isJDWPPort(port int) bool {
	jdwpPorts := []int{5005, 8000, 8787, 9999, 18000}
	for _, p := range jdwpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// probeJDWP 探测JDWP协议
func probeJDWP(host string, port int) (string, string) {
	Common.LogDebug(fmt.Sprintf("开始JDWP探测: %s:%d", host, port))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("JDWP连接失败: %s:%d - %v", host, port, err))
		return "", ""
	}
	defer conn.Close()

	// 方法1: 标准JDWP握手
	handshakeRequest := []byte("JDWP-Handshake")
	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	_, err = conn.Write(handshakeRequest)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("JDWP发送握手失败: %s:%d - %v", host, port, err))
		// 连接成功但写入失败，可能是JDWP但配置异常
		return "JDWP可能存在(写入失败)", "jdwp"
	}

	// 读取响应
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("JDWP读取响应失败: %s:%d - %v", host, port, err))
		// 能连接但无响应，在常见JDWP端口上很可能是JDWP
		if isCommonJDWPPort(port) {
			Common.LogInfo(fmt.Sprintf("疑似JDWP服务(无响应): %s:%d", host, port))
			return "JDWP疑似(无握手响应)", "jdwp"
		}
		return "", ""
	}

	if n == 0 {
		Common.LogDebug(fmt.Sprintf("JDWP收到空响应: %s:%d", host, port))
		if isCommonJDWPPort(port) {
			return "JDWP疑似(空响应)", "jdwp"
		}
		return "", ""
	}

	responseStr := string(response[:n])
	Common.LogDebug(fmt.Sprintf("JDWP收到响应: %s:%d - [%s] (长度:%d)", host, port, responseStr, n))

	// 检查标准JDWP握手响应
	if responseStr == "JDWP-Handshake" {
		Common.LogError(fmt.Sprintf("发现JDWP未授权访问: %s:%d", host, port))
		return "JDWP-Handshake", "jdwp"
	}

	// 检查响应是否包含JDWP特征
	if strings.Contains(strings.ToLower(responseStr), "jdwp") {
		Common.LogInfo(fmt.Sprintf("发现JDWP服务: %s:%d - %s", host, port, responseStr))
		return responseStr, "jdwp"
	}

	// 方法2: 尝试JDWP版本命令
	if tryJDWPVersionCommand(conn, host, port) {
		return "JDWP服务(版本命令响应)", "jdwp"
	}

	Common.LogDebug(fmt.Sprintf("JDWP握手失败，响应不匹配: %s:%d", host, port))
	return "", ""
}

// isCommonJDWPPort 检查是否为常见JDWP端口
func isCommonJDWPPort(port int) bool {
	commonPorts := []int{5005, 8000} // 最常见的JDWP端口
	for _, p := range commonPorts {
		if port == p {
			return true
		}
	}
	return false
}

// tryJDWPVersionCommand 尝试发送JDWP版本命令
func tryJDWPVersionCommand(conn net.Conn, host string, port int) bool {
	// JDWP版本命令包
	versionCmd := []byte{
		0x00, 0x00, 0x00, 0x0B, // 长度: 11字节
		0x00, 0x00, 0x00, 0x01, // ID: 1
		0x00,       // 标志: 0
		0x01, 0x01, // 命令集: 1, 命令: 1 (VirtualMachine.Version)
	}

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	_, err := conn.Write(versionCmd)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("JDWP版本命令发送失败: %s:%d - %v", host, port, err))
		return false
	}

	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil || n < 11 {
		Common.LogDebug(fmt.Sprintf("JDWP版本命令响应失败: %s:%d - %v", host, port, err))
		return false
	}

	// 检查JDWP响应格式
	if n >= 11 && response[8] == 0x80 { // 检查reply标志
		Common.LogInfo(fmt.Sprintf("JDWP版本命令成功: %s:%d", host, port))
		return true
	}

	return false
}

// sendProbeAndGetResponse 发送探测包并获取响应
func sendProbeAndGetResponse(host string, port int, payload []byte) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 设置超时
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// 发送探测数据
	if len(payload) > 0 {
		_, err = conn.Write(payload)
		if err != nil {
			return ""
		}
	}

	// 读取响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	return strings.TrimSpace(string(buffer[:n]))
}

// identifyServiceFromBanner 从Banner快速识别服务类型
func identifyServiceFromBanner(banner string, port int) string {
	bannerLower := strings.ToLower(banner)

	// JDWP检测 - 完全基于Banner内容，不依赖端口号
	if strings.Contains(bannerLower, "jdwp-handshake") {
		return "jdwp"
	}

	// 常见服务特征识别
	if strings.Contains(bannerLower, "ssh") {
		return "ssh"
	}
	if strings.Contains(bannerLower, "ftp") {
		return "ftp"
	}
	if strings.Contains(bannerLower, "mysql") {
		return "mysql"
	}
	if strings.Contains(bannerLower, "microsoft-iis") {
		return "http"
	}
	if strings.Contains(bannerLower, "apache") {
		return "http"
	}
	if strings.Contains(bannerLower, "nginx") {
		return "http"
	}
	if strings.Contains(bannerLower, "redis") {
		return "redis"
	}
	if strings.Contains(bannerLower, "mongodb") {
		return "mongodb"
	}
	if strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "postfix") {
		return "smtp"
	}
	if strings.Contains(bannerLower, "pop3") {
		return "pop3"
	}
	if strings.Contains(bannerLower, "imap") {
		return "imap"
	}
	if strings.Contains(bannerLower, "telnet") {
		return "telnet"
	}

	// 基于端口的默认识别（但不包括JDWP，JDWP只通过协议探测识别）
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 587, 465:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8000, 8080, 8081, 8090:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443, 8443:
		return "https"
	case 445:
		return "smb"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	default:
		return "tcp"
	}
}

// isHttpPort 判断是否为HTTP端口
func isHttpPort(port int) bool {
	httpPorts := []int{80, 443, 8000, 8080, 8081, 8090, 8443, 9000, 7001, 8001, 8008}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// tryQuickHttpProbe 快速HTTP探测 - 使用优化检测模块
func tryQuickHttpProbe(host string, port int) (string, string) {
	// 创建临时连接进行优化检测
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 1*time.Second)
	if err != nil {
		return "", "http"
	}

	// 使用优化的HTTP检测
	if httpResult := OptimizedHttpDetect(host, port, conn); httpResult != nil && httpResult.Error == "" {
		return httpResult.Title, httpResult.Protocol
	}

	return "", "http"
}

// quickHttpRequest 快速HTTP请求获取标题
func quickHttpRequest(host string, port int, scheme string) string {
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	client := &http.Client{
		Timeout: 2 * time.Second, // 2秒超时
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: 1 * time.Second,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// 读取HTML内容提取标题
	buffer := make([]byte, 4096) // 只读前4KB
	n, _ := resp.Body.Read(buffer)
	content := string(buffer[:n])

	// 提取标题
	titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(content)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		return title
	}

	return ""
}
