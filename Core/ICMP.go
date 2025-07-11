package Core

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/net/icmp"
)

var (
	AliveHosts []string                    // 存活主机列表
	ExistHosts = make(map[string]struct{}) // 已发现主机记录
	livewg     sync.WaitGroup              // 存活检测等待组
)

// CheckLive 检测主机存活状态
func CheckLive(hostslist []string, Ping bool) []string {
	// 创建主机通道
	chanHosts := make(chan string, len(hostslist))

	// 处理存活主机
	go handleAliveHosts(chanHosts, hostslist, Ping)

	// 根据Ping参数选择检测方式
	if Ping {
		// 使用ping方式探测
		RunPing(hostslist, chanHosts)
	} else {
		probeWithICMP(hostslist, chanHosts)
	}

	// 等待所有检测完成
	livewg.Wait()
	close(chanHosts)

	// 输出存活统计信息
	printAliveStats(hostslist)

	return AliveHosts
}

// IsContain 检查切片中是否包含指定元素
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func handleAliveHosts(chanHosts chan string, hostslist []string, isPing bool) {
	for ip := range chanHosts {
		if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
			ExistHosts[ip] = struct{}{}
			AliveHosts = append(AliveHosts, ip)

			// 使用Output系统保存存活主机信息
			protocol := "ICMP"
			if isPing {
				protocol = "PING"
			}

			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.HOST,
				Target: ip,
				Status: "alive",
				Details: map[string]interface{}{
					"protocol": protocol,
				},
			}
			Common.SaveResult(result)

			// 保留原有的控制台输出
			if !Common.Silent {
				Common.LogInfo(Common.GetText("target_alive", ip, protocol))
			}
		}
		livewg.Done()
	}
}

// probeWithICMP 使用ICMP方式探测
func probeWithICMP(hostslist []string, chanHosts chan string) {
	// 尝试监听本地ICMP
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		RunIcmp1(hostslist, conn, chanHosts)
		return
	}

	Common.LogError(Common.GetText("icmp_listen_failed", err))
	Common.LogBase(Common.GetText("trying_no_listen_icmp"))

	// 尝试无监听ICMP探测
	conn2, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
	if err == nil {
		defer conn2.Close()
		RunIcmp2(hostslist, chanHosts)
		return
	}

	Common.LogBase(Common.GetText("icmp_connect_failed", err))
	Common.LogBase(Common.GetText("insufficient_privileges"))
	Common.LogBase(Common.GetText("switching_to_ping"))

	// 降级使用ping探测
	RunPing(hostslist, chanHosts)
}

// printAliveStats 打印存活统计信息
func printAliveStats(hostslist []string) {
	// 大规模扫描时输出 /16 网段统计
	if len(hostslist) > 1000 {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, Common.LiveTop, true)
		for i := 0; i < len(arrTop); i++ {
			Common.LogInfo(Common.GetText("subnet_16_alive", arrTop[i], arrLen[i]))
		}
	}

	// 输出 /24 网段统计
	if len(hostslist) > 256 {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, Common.LiveTop, false)
		for i := 0; i < len(arrTop); i++ {
			Common.LogInfo(Common.GetText("subnet_24_alive", arrTop[i], arrLen[i]))
		}
	}
}

// RunIcmp1 使用ICMP批量探测主机存活(监听模式)
func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false

	// 启动监听协程
	go func() {
		for {
			if endflag {
				return
			}
			// 接收ICMP响应
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	// 发送ICMP请求 - 集成速率控制
	for _, host := range hostslist {
		// 应用简化的智能速率控制 - 快速扫描 + 基础反检测
		Common.SmartWait()

		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		_, err := conn.WriteTo(IcmpByte, dst)

		// 记录发包统计
		Common.PerfMonitor.RecordPacket(err == nil)
	}

	// 等待响应 - 使用配置的超时时间
	start := time.Now()
	for {
		// 所有主机都已响应则退出
		if len(AliveHosts) == len(hostslist) {
			break
		}

		// 根据主机数量和配置设置超时时间
		since := time.Since(start)
		wait := time.Duration(Common.PingTimeout) * time.Second
		if len(hostslist) <= 256 {
			wait = time.Duration(Common.PingTimeout/2) * time.Second
		}

		if since > wait {
			break
		}

		// 每隔一段时间进行简化的自适应速率控制
		if since.Seconds() > 5 {
			// 获取统计信息并进行自适应调整
			sent, _, _, successRate := Common.PerfMonitor.GetStats()
			if sent > 0 {
				Common.AutoAdaptRate(successRate/100, sent) // 转换为0-1的成功率
			}
		}
	}

	endflag = true
	conn.Close()
}

// RunIcmp2 使用ICMP并发探测主机存活(无监听模式)
func RunIcmp2(hostslist []string, chanHosts chan string) {
	// 控制并发数
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}

	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			// 应用简化的智能速率控制 - 快速扫描 + 基础反检测
			Common.SmartWait()

			success := icmpalive(host)
			// 记录发包统计
			Common.PerfMonitor.RecordPacket(success)

			if success {
				livewg.Add(1)
				chanHosts <- host
			}
		}(host)
	}

	wg.Wait()
	close(limiter)
}

// icmpalive 检测主机ICMP是否存活（增强版）
func icmpalive(host string) bool {
	startTime := time.Now()

	// 支持本地网卡指定
	var localAddr *net.IPAddr
	if Common.LocalInterface != "" {
		localIP := net.ParseIP(Common.LocalInterface)
		if localIP != nil {
			localAddr = &net.IPAddr{IP: localIP}
		}
	}

	// 解析目标地址
	targetAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}

	// 建立ICMP连接，支持本地网卡指定
	var conn net.Conn
	timeout := time.Duration(Common.PingTimeout) * time.Second

	if localAddr != nil {
		// 使用指定的本地网卡
		conn, err = net.DialIP("ip4:icmp", localAddr, targetAddr)
	} else {
		// 使用默认网卡
		conn, err = net.DialTimeout("ip4:icmp", host, timeout)
	}

	if err != nil {
		return false
	}
	defer conn.Close()

	// 设置超时时间
	if err := conn.SetDeadline(startTime.Add(timeout)); err != nil {
		return false
	}

	// 构造并发送ICMP请求
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	// 接收ICMP响应
	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

// RunPing 使用系统Ping命令并发探测主机存活（增强版）
func RunPing(hostslist []string, chanHosts chan string) {
	var wg sync.WaitGroup
	// 限制并发数为50
	limiter := make(chan struct{}, 50)

	// 并发探测
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}

		go func(host string) {
			defer func() {
				<-limiter
				wg.Done()
			}()

			// 应用简化的智能速率控制 - 快速扫描 + 基础反检测
			Common.SmartWait()

			success := ExecCommandPing(host)
			// 记录发包统计
			Common.PerfMonitor.RecordPacket(success)

			if success {
				livewg.Add(1)
				chanHosts <- host
			}
		}(host)
	}

	wg.Wait()
}

// ExecCommandPing 执行系统Ping命令检测主机存活
func ExecCommandPing(ip string) bool {
	// 过滤黑名单字符
	forbiddenChars := []string{";", "&", "|", "`", "$", "\\", "'", "%", "\"", "\n"}
	for _, char := range forbiddenChars {
		if strings.Contains(ip, char) {
			return false
		}
	}

	var command *exec.Cmd
	// 根据操作系统选择不同的ping命令
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false")
	default: // linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false")
	}

	// 捕获命令输出
	var outinfo bytes.Buffer
	command.Stdout = &outinfo

	// 执行命令
	if err := command.Start(); err != nil {
		return false
	}

	if err := command.Wait(); err != nil {
		return false
	}

	// 分析输出结果
	output := outinfo.String()
	return strings.Contains(output, "true") && strings.Count(output, ip) > 2
}

// makemsg 构造ICMP echo请求消息
func makemsg(host string) []byte {
	msg := make([]byte, 40)

	// 获取标识符
	id0, id1 := genIdentifier(host)

	// 设置ICMP头部
	msg[0] = 8                      // Type: Echo Request
	msg[1] = 0                      // Code: 0
	msg[2] = 0                      // Checksum高位(待计算)
	msg[3] = 0                      // Checksum低位(待计算)
	msg[4], msg[5] = id0, id1       // Identifier
	msg[6], msg[7] = genSequence(1) // Sequence Number

	// 计算校验和
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)  // 设置校验和高位
	msg[3] = byte(check & 255) // 设置校验和低位

	return msg
}

// checkSum 计算ICMP校验和
func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)

	// 按16位累加
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}

	// 处理奇数长度情况
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}

	// 将高16位加到低16位
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// 取反得到校验和
	return uint16(^sum)
}

// genSequence 生成ICMP序列号
func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)  // 高8位
	ret2 := byte(v & 255) // 低8位
	return ret1, ret2
}

// genIdentifier 根据主机地址生成标识符
func genIdentifier(host string) (byte, byte) {
	return host[0], host[1] // 使用主机地址前两个字节
}

// ArrayCountValueTop 统计IP地址段存活数量并返回TOP N结果
func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}

	// 统计各网段出现次数
	segmentCounts := make(map[string]int)
	for _, ip := range arrInit {
		segments := strings.Split(ip, ".")
		if len(segments) != 4 {
			continue
		}

		// 根据flag确定统计B段还是C段
		var segment string
		if flag {
			segment = fmt.Sprintf("%s.%s", segments[0], segments[1]) // B段
		} else {
			segment = fmt.Sprintf("%s.%s.%s", segments[0], segments[1], segments[2]) // C段
		}

		segmentCounts[segment]++
	}

	// 创建副本用于排序
	sortMap := make(map[string]int)
	for k, v := range segmentCounts {
		sortMap[k] = v
	}

	// 获取TOP N结果
	for i := 0; i < length && len(sortMap) > 0; i++ {
		maxSegment := ""
		maxCount := 0

		// 查找当前最大值
		for segment, count := range sortMap {
			if count > maxCount {
				maxCount = count
				maxSegment = segment
			}
		}

		// 添加到结果集
		arrTop = append(arrTop, maxSegment)
		arrLen = append(arrLen, maxCount)

		// 从待处理map中删除已处理项
		delete(sortMap, maxSegment)
	}

	return
}
