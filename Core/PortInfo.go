package Core

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

// ServiceInfo 定义服务识别的结果信息
type ServiceInfo struct {
	Name    string            // 服务名称,如 http、ssh 等
	Banner  string            // 服务返回的横幅信息
	Version string            // 服务版本号
	Extras  map[string]string // 其他额外信息,如操作系统、产品名等
}

// Result 定义单次探测的结果
type Result struct {
	Service Service           // 识别出的服务信息
	Banner  string            // 服务横幅
	Extras  map[string]string // 额外信息
	Send    []byte            // 发送的探测数据
	Recv    []byte            // 接收到的响应数据
}

// Service 定义服务的基本信息
type Service struct {
	Name   string            // 服务名称
	Extras map[string]string // 服务的额外属性
}

// Info 定义单个端口探测的上下文信息
type Info struct {
	Address string   // 目标IP地址
	Port    int      // 目标端口
	Conn    net.Conn // 网络连接
	Result  Result   // 探测结果
	Found   bool     // 是否成功识别服务
}

// PortInfoScanner 定义端口服务识别器
type PortInfoScanner struct {
	Address string        // 目标IP地址
	Port    int           // 目标端口
	Conn    net.Conn      // 网络连接
	Timeout time.Duration // 超时时间
	info    *Info         // 探测上下文
}

// NewPortInfoScanner 创建新的端口服务识别器实例
func NewPortInfoScanner(addr string, port int, conn net.Conn, timeout time.Duration) *PortInfoScanner {
	return &PortInfoScanner{
		Address: addr,
		Port:    port,
		Conn:    conn,
		Timeout: timeout,
		info: &Info{
			Address: addr,
			Port:    port,
			Conn:    conn,
			Result: Result{
				Service: Service{},
			},
		},
	}
}

// Identify 执行服务识别,返回识别结果 - 使用gogo风格的轻量级识别
func (s *PortInfoScanner) Identify() (*ServiceInfo, error) {
	Common.LogDebug(fmt.Sprintf("开始gogo风格服务识别 %s:%d", s.Address, s.Port))

	// 使用gogo风格的优化识别
	result := OptimizedIdentifyService(s.Address, s.Port, s.Conn, s.Timeout)
	if result != nil {
		serviceInfo := &ServiceInfo{
			Name:    result.Service,
			Banner:  result.Banner,
			Version: result.Version,
			Extras:  result.ExtraInfo,
		}
		Common.LogDebug(fmt.Sprintf("gogo风格识别完成 %s:%d => %s", s.Address, s.Port, serviceInfo.Name))
		return serviceInfo, nil
	}

	// 如果gogo识别失败，使用基础端口推测
	serviceName := guessServiceByPortSimple(s.Port)
	serviceInfo := &ServiceInfo{
		Name:    serviceName,
		Banner:  "",
		Version: "",
		Extras:  make(map[string]string),
	}

	Common.LogDebug(fmt.Sprintf("基础端口推测 %s:%d => %s", s.Address, s.Port, serviceName))
	return serviceInfo, nil
}

// guessServiceByPortSimple 简单的端口服务推测
func guessServiceByPortSimple(port int) string {
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

// ===== 以下是原有nmap系统代码，已注释不再使用 =====

// PortInfo 执行端口服务识别的主要逻辑 - 已替换为gogo风格识别
func (i *Info) PortInfo() {
	// 注释：原有的复杂nmap识别系统已被gogo风格系统替代
	// 现在统一使用 OptimizedIdentifyService 进行识别
	Common.LogDebug("PortInfo: 已替换为gogo风格识别，此函数仅保留兼容性")

	// 标记为未知服务，让上层使用gogo系统
	if strings.TrimSpace(i.Result.Service.Name) == "" {
		i.Result.Service.Name = "unknown"
	}

	// === 以下原有nmap系统代码已注释 ===

	// // 1. 首先尝试读取服务的初始响应
	// if response, err := i.Read(); err == nil && len(response) > 0 {
	//     Common.LogDebug(fmt.Sprintf("收到初始响应: %d 字节", len(response)))
	//
	//     // 使用基础探测器检查响应
	//     Common.LogDebug("尝试使用基础探测器(null/common)检查响应")
	//     if i.tryProbes(response, []*Probe{null, common}) {
	//         Common.LogDebug("基础探测器匹配成功")
	//         return
	//     }
	//     Common.LogDebug("基础探测器未匹配")
	// } else if err != nil {
	//     Common.LogDebug(fmt.Sprintf("读取初始响应失败: %v", err))
	// }
	//
	// // 记录已使用的探测器,避免重复使用
	// usedProbes := make(map[string]struct{})
	//
	// // 2. 尝试使用端口专用探测器
	// Common.LogDebug(fmt.Sprintf("尝试使用端口 %d 的专用探测器", i.Port))
	// if i.processPortMapProbes(usedProbes) {
	//     Common.LogDebug("端口专用探测器匹配成功")
	//     return
	// }
	// Common.LogDebug("端口专用探测器未匹配")
	//
	// // 3. 使用默认探测器列表
	// Common.LogDebug("尝试使用默认探测器列表")
	// if i.processDefaultProbes(usedProbes) {
	//     Common.LogDebug("默认探测器匹配成功")
	//     return
	// }
	// Common.LogDebug("默认探测器未匹配")
}

// === 以下函数保留但已被gogo系统替代，不再调用nmap系统 ===

// tryProbes 尝试使用指定的探测器列表检查响应 - 已停用
func (i *Info) tryProbes(response []byte, probes []*Probe) bool {
	// 注释：不再使用nmap探测器，统一使用gogo系统
	return false
}

// processPortMapProbes 处理端口映射中的专用探测器 - 已停用
func (i *Info) processPortMapProbes(usedProbes map[string]struct{}) bool {
	// 注释：不再使用nmap的PortMap，已替换为gogo风格识别
	return false
}

// processDefaultProbes 处理默认探测器列表 - 已停用
func (i *Info) processDefaultProbes(usedProbes map[string]struct{}) bool {
	// 注释：不再使用nmap的DefaultMap，已替换为gogo风格识别
	return false
}

// GetInfo 分析响应数据并提取服务信息 - 已停用
func (i *Info) GetInfo(response []byte, probe *Probe) {
	// 注释：不再使用nmap的探测器匹配，已替换为gogo风格识别
	return
}

// processMatches 处理匹配规则集 - 已停用
func (i *Info) processMatches(response []byte, matches *[]Match) (bool, *Match) {
	// 注释：不再使用nmap的匹配规则，已替换为gogo风格识别
	return false, nil
}

// handleHardMatch 处理硬匹配结果 - 已停用
func (i *Info) handleHardMatch(response []byte, match *Match) {
	// 注释：不再使用nmap的匹配处理，已替换为gogo风格识别
	return
}

// handleNoMatch 处理未匹配情况 - 已停用
func (i *Info) handleNoMatch(response []byte, result *Result, softFound bool, softMatch Match) {
	// 注释：不再使用nmap的未匹配处理，已替换为gogo风格识别
	return
}

// Connect 建立连接并发送探测数据 - 已停用
func (i *Info) Connect(data []byte) []byte {
	// 注释：不再使用nmap的连接方式，gogo系统会复用现有连接
	return nil
}

// Read 读取服务响应 - 已停用
func (i *Info) Read() ([]byte, error) {
	// 注释：不再使用nmap的读取方式，gogo系统有优化的读取逻辑
	return nil, fmt.Errorf("已替换为gogo风格识别")
}

// ===== 保留一些通用的辅助函数 =====

// 保留一些可能被其他地方使用的结构和方法，但内部不再调用nmap系统
