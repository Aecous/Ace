package Common

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// 简化的速率限制配置 - 学习fscanx和gogo的简洁设计
var (
	// 基础配置
	MaxBandwidth   float64 = 1.0 * 1024 * 1024 // 最大带宽 字节/秒
	ICMPPacketSize int     = 64                // ICMP数据包大小，单位字节
	PingRate       float64 = 0.1               // 速率倍数 (0.0-1.0)
	PingTimeout    int64   = 6                 // ping超时时间(秒)
	LocalInterface string  = ""                // 本地网卡接口IP

	// 动态计算的速率参数
	PacketsPerSecond float64
	TokenBucketSize  int64
	PacketInterval   time.Duration

	// 令牌桶限流器
	RateLimiter *TokenBucket

	// 简化的流量模拟配置 - 专注于反检测而非模拟人类
	RateScanMode string  = "balanced" // fast, balanced, stealth
	JitterRatio  float64 = 0.15       // 15%随机抖动，避免固定频率被检测
	BurstEnabled bool    = true       // 启用随机突发，模拟正常网络行为
	BurstChance  float64 = 0.05       // 5%突发概率
)

// TokenBucket 简化的令牌桶结构 - 学习fscanx的设计
type TokenBucket struct {
	capacity   int64      // 桶容量
	tokens     int64      // 当前令牌数
	refillRate int64      // 填充速率 (令牌/秒)
	lastRefill time.Time  // 上次填充时间
	mutex      sync.Mutex // 并发保护
}

// NewTokenBucket 创建新的令牌桶
func NewTokenBucket(capacity int64, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // 初始时桶满
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Wait 等待获取指定数量的令牌 - 学习fscanx的简单实现
func (tb *TokenBucket) Wait(count int64) {
	for {
		if tb.TryConsume(count) {
			return
		}
		time.Sleep(time.Millisecond) // 1ms精度，减少CPU消耗
	}
}

// TryConsume 尝试消费指定数量的令牌
func (tb *TokenBucket) TryConsume(count int64) bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	tb.refill()

	if tb.tokens >= count {
		tb.tokens -= count
		return true
	}
	return false
}

// refill 填充令牌桶
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)

	if elapsed > 0 {
		tokensToAdd := int64(elapsed.Seconds()) * tb.refillRate
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// GetTokenCount 获取当前令牌数量
func (tb *TokenBucket) GetTokenCount() int64 {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.refill()
	return tb.tokens
}

// InitRateLimit 初始化速率限制系统 - 简化版本
func InitRateLimit() {
	// 计算实际速率 - 学习fscanx的算法
	actualBandwidth := MaxBandwidth * PingRate
	PacketsPerSecond = actualBandwidth / float64(ICMPPacketSize)
	TokenBucketSize = int64(PacketsPerSecond * 2) // 桶容量为2秒的包量
	PacketInterval = time.Duration(float64(time.Second) / PacketsPerSecond)

	// 创建令牌桶
	RateLimiter = NewTokenBucket(TokenBucketSize, int64(PacketsPerSecond))

	LogInfo(fmt.Sprintf("速率控制初始化: %.0f pps, 间隔: %v, 模式: %s",
		PacketsPerSecond, PacketInterval, RateScanMode))
}

// SmartWait 智能等待 - 快速扫描 + 基础反检测
func SmartWait() {
	// 1. 基础令牌桶限制
	RateLimiter.Wait(1)

	// 2. 根据扫描模式应用不同的等待策略
	switch RateScanMode {
	case "fast":
		FastWait()
	case "stealth":
		StealthWait()
	default: // balanced
		BalancedWait()
	}
}

// FastWait 快速模式 - 最小化延迟，只保留微小抖动
func FastWait() {
	// 只在30%的时候添加微小的随机延迟，避免完全规律的发包
	if rand.Float64() < 0.3 {
		microDelay := time.Microsecond * time.Duration(rand.Intn(100))
		time.Sleep(microDelay)
	}
}

// BalancedWait 平衡模式 - 速度与隐蔽性并重
func BalancedWait() {
	// 基础延迟
	baseDelay := PacketInterval

	// 随机抖动避免固定频率 - 关键的反检测技术
	if JitterRatio > 0 {
		jitter := float64(baseDelay) * JitterRatio
		randomJitter := time.Duration(rand.Float64()*jitter - jitter/2)
		baseDelay += randomJitter
	}

	// 随机突发模拟正常网络行为
	if BurstEnabled && rand.Float64() < BurstChance {
		baseDelay = baseDelay / 2 // 突发时缩短间隔
	}

	if baseDelay > 0 {
		time.Sleep(baseDelay)
	}
}

// StealthWait 隐蔽模式 - 更大的随机化
func StealthWait() {
	// 基础延迟加倍
	baseDelay := PacketInterval * 2

	// 更大的随机抖动 (50%)
	jitter := float64(baseDelay) * 0.5
	randomJitter := time.Duration(rand.Float64() * jitter)

	time.Sleep(baseDelay + randomJitter)
}

// SetRateScanMode 设置速率扫描模式
func SetRateScanMode(mode string) error {
	switch mode {
	case "fast", "balanced", "stealth":
		RateScanMode = mode
		LogInfo(fmt.Sprintf("速率扫描模式设置为: %s", mode))
		return nil
	default:
		return fmt.Errorf("未知的速率扫描模式: %s", mode)
	}
}

// UpdatePingRate 动态更新速率倍数
func UpdatePingRate(newRate float64) {
	if newRate <= 0 || newRate > 1.0 {
		return
	}

	PingRate = newRate
	// 重新初始化速率限制
	InitRateLimit()
	LogInfo(fmt.Sprintf("速率已调整为: %.2f", newRate))
}

// GetRateStatus 获取当前速率状态
func GetRateStatus() string {
	tokens := RateLimiter.GetTokenCount()

	return fmt.Sprintf("模式: %s | 速率: %.2f | PPS: %.0f | 令牌: %d/%d",
		RateScanMode, PingRate, PacketsPerSecond, tokens, TokenBucketSize)
}

// AutoAdaptRate 修复的自适应速率调整 - 专门用于ICMP ping
func AutoAdaptRate(successRate float64, packetsSent int64) {
	// 只在发送了足够多的包后才进行调整，且仅用于ICMP ping
	if packetsSent < 100 {
		return
	}

	// 自适应算法 - 只针对ICMP ping的丢包率进行调整
	// 对于端口扫描，端口关闭是正常情况，不应触发降速
	if successRate < 0.5 { // ICMP ping成功率低于50%才降速
		newRate := PingRate * 0.9
		if newRate < 0.05 {
			newRate = 0.05
		}
		UpdatePingRate(newRate)
		LogInfo("检测到ICMP丢包率高，降低ping速率")
	} else if successRate > 0.9 { // ICMP ping成功率高于90%
		newRate := PingRate * 1.05
		if newRate > 1.0 {
			newRate = 1.0
		}
		UpdatePingRate(newRate)
		LogInfo("网络状况良好，提高ping速率")
	}
}

// 简化的性能监控
type SimplePerformanceMonitor struct {
	StartTime      time.Time
	PacketsSent    int64
	PacketsSuccess int64
	mutex          sync.RWMutex
}

var PerfMonitor = &SimplePerformanceMonitor{
	StartTime: time.Now(),
}

// RecordPacket 记录发包统计
func (pm *SimplePerformanceMonitor) RecordPacket(success bool) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.PacketsSent++
	if success {
		pm.PacketsSuccess++
	}
}

// GetStats 获取统计信息
func (pm *SimplePerformanceMonitor) GetStats() (int64, int64, float64, float64) {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	elapsed := time.Since(pm.StartTime).Seconds()
	pps := float64(pm.PacketsSent) / elapsed
	successRate := float64(pm.PacketsSuccess) / float64(pm.PacketsSent) * 100

	return pm.PacketsSent, pm.PacketsSuccess, pps, successRate
}

// 预设的扫描场景配置
var ScanScenarios = map[string]ScenarioConfig{
	"fast": {
		Mode:           "fast",
		RateMultiplier: 0.8,
		Description:    "快速扫描，最大化速度",
	},
	"balanced": {
		Mode:           "balanced",
		RateMultiplier: 0.3,
		Description:    "平衡模式，速度与隐蔽性并重",
	},
	"stealth": {
		Mode:           "stealth",
		RateMultiplier: 0.1,
		Description:    "隐蔽模式，最大化反检测能力",
	},
}

type ScenarioConfig struct {
	Mode           string
	RateMultiplier float64
	Description    string
}

// ApplyScenario 应用预设场景
func ApplyScenario(scenario string) error {
	config, exists := ScanScenarios[scenario]
	if !exists {
		return fmt.Errorf("未知场景: %s", scenario)
	}

	SetRateScanMode(config.Mode)
	UpdatePingRate(config.RateMultiplier)

	LogInfo(fmt.Sprintf("已应用%s场景: %s", scenario, config.Description))
	return nil
}

// PortScanWait 端口扫描专用的速率控制 - 比ICMP ping更激进
func PortScanWait() {
	// 端口扫描不需要像ICMP那样严格的速率控制
	// 根据扫描模式应用轻量级限制
	switch RateScanMode {
	case "fast":
		// 快速模式：几乎无延迟
		if rand.Float64() < 0.1 {
			time.Sleep(time.Microsecond * time.Duration(rand.Intn(50)))
		}
	case "stealth":
		// 隐蔽模式：适中延迟
		if rand.Float64() < 0.5 {
			time.Sleep(time.Millisecond * time.Duration(rand.Intn(10)))
		}
	default: // balanced
		// 平衡模式：轻微延迟
		if rand.Float64() < 0.2 {
			time.Sleep(time.Microsecond * time.Duration(rand.Intn(200)))
		}
	}
}
