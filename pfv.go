package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 版本信息
const PFV_VERSION = "1.0.0"

// 校准文件路径
const PFV_CALIBRATION_MARKER = "/tmp/pfv_calibrated"

// 常量定义
const (
	// 默认API密钥
	PFV_DEFAULT_API_KEY = "pfv-api-key-2023"
)

// ===================== 配置相关 =====================

// 配置结构
type PfvConfig struct {
	Ports     []int  `json:"ports"`
	ApiPort   int    `json:"api_port"`
	LogPath   string `json:"log_path"`
	DataPath  string `json:"data_path"`
	Threshold uint64 `json:"threshold"` // 默认阈值，单位：字节
}

// 加载配置文件
func loadPfvConfig(configPath string) (*PfvConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config PfvConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证端口范围
	for _, port := range config.Ports {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("无效的端口号: %d，端口范围应为1-65535", port)
		}
	}

	// 设置默认值
	if config.ApiPort == 0 {
		config.ApiPort = 56789
	}
	if config.LogPath == "" {
		config.LogPath = "/var/log/pfv/pfv.log"
	}
	if config.DataPath == "" {
		config.DataPath = "/var/lib/pfv/pfv.json"
	}
	if config.Threshold == 0 {
		config.Threshold = 20 * 1024 * 1024 * 1024 // 默认20GB
	}

	return &config, nil
}

// ===================== 数据存储相关 =====================

// 端口统计结构
type PfvPortStats struct {
	Port          int    `json:"port"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	LastBytesSent uint64 `json:"last_bytes_sent"`
	LastBytesRecv uint64 `json:"last_bytes_recv"`
	Threshold     uint64 `json:"threshold"`
	Blocked       bool   `json:"blocked"`
}

// 状态存储结构
type PfvStorage struct {
	Stats map[int]*PfvPortStats `json:"stats"`
	mutex sync.Mutex
}

// 创建新的存储实例
func NewPfvStorage() *PfvStorage {
	return &PfvStorage{
		Stats: make(map[int]*PfvPortStats),
	}
}

// 保存数据到文件
func (s *PfvStorage) SaveToFile(filePath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化数据失败: %v", err)
	}

	// 确保目录存在
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 使用临时文件和原子操作避免数据损坏
	tmpFile := filePath + ".tmp"
	if err := ioutil.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("写入临时文件失败: %v", err)
	}

	// 原子替换文件
	if err := os.Rename(tmpFile, filePath); err != nil {
		// 尝试删除临时文件
		os.Remove(tmpFile)
		return fmt.Errorf("替换文件失败: %v", err)
	}

	return nil
}

// 从文件加载数据
func (s *PfvStorage) LoadFromFile(filePath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 初始化空数据以防文件读取或解析失败
	s.Stats = make(map[int]*PfvPortStats)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// 文件不存在，使用空数据
		return nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %v", err)
	}

	// 空文件处理
	if len(data) == 0 {
		return nil
	}

	var tempPfvStorage PfvStorage
	if err := json.Unmarshal(data, &tempPfvStorage); err != nil {
		return fmt.Errorf("解析数据失败: %v", err)
	}

	s.Stats = tempPfvStorage.Stats
	return nil
}

// 添加或更新端口统计
func (s *PfvStorage) UpdatePort(port int, threshold uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.Stats[port]; !exists {
		s.Stats[port] = &PfvPortStats{
			Port:      port,
			Threshold: threshold,
		}
	} else {
		// 只更新阈值，保留其他数据
		s.Stats[port].Threshold = threshold
	}
}

// 移除端口统计
func (s *PfvStorage) RemovePort(port int) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.Stats[port]; exists {
		delete(s.Stats, port)
		return true
	}
	return false
}

// 重置端口流量统计
func (s *PfvStorage) ResetPort(port int) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if stats, exists := s.Stats[port]; exists {
		stats.BytesSent = 0
		stats.BytesReceived = 0
		stats.LastBytesSent = 0
		stats.LastBytesRecv = 0
		return true
	}
	return false
}

// 获取所有端口统计
func (s *PfvStorage) GetAllStats() map[int]*PfvPortStats {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 创建副本以避免并发问题
	result := make(map[int]*PfvPortStats)
	for port, stats := range s.Stats {
		statsCopy := *stats
		result[port] = &statsCopy
	}
	return result
}

// 获取指定端口统计
func (s *PfvStorage) GetPortStats(port int) (*PfvPortStats, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	stats, exists := s.Stats[port]
	if !exists {
		return nil, false
	}

	// 返回副本以避免并发问题
	statsCopy := *stats
	return &statsCopy, true
}

// 设置端口阻断状态
func (s *PfvStorage) SetBlockedStatus(port int, blocked bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if stats, exists := s.Stats[port]; exists {
		stats.Blocked = blocked
		return true
	}
	return false
}

// ===================== 监控相关 =====================

// 获取端口当前流量
func getPfvPortTraffic(port int) (uint64, uint64, error) {
	// 使用netstat命令获取网络流量统计 - 更可靠的方式
	tcpCmd := exec.Command("sh", "-c", fmt.Sprintf("netstat -tn 2>/dev/null | grep ':%d '", port))
	udpCmd := exec.Command("sh", "-c", fmt.Sprintf("netstat -un 2>/dev/null | grep ':%d '", port))

	// 设置命令执行超时
	tcpCtx, tcpCancel := context.WithTimeout(context.Background(), 3*time.Second)
	udpCtx, udpCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer tcpCancel()
	defer udpCancel()

	// 执行命令并正确处理错误
	tcpCmd.Stderr = nil // 忽略stderr输出
	udpCmd.Stderr = nil

	tcpCmd = exec.CommandContext(tcpCtx, tcpCmd.Path, tcpCmd.Args...)
	udpCmd = exec.CommandContext(udpCtx, udpCmd.Path, udpCmd.Args...)

	tcpOutput, tcpErr := tcpCmd.Output()
	udpOutput, udpErr := udpCmd.Output()

	// 忽略某些预期的错误，如命令未找到或没有匹配结果
	if tcpErr != nil && !isExpectedCommandError(tcpErr) {
		return 0, 0, fmt.Errorf("TCP命令执行失败: %v", tcpErr)
	}

	if udpErr != nil && !isExpectedCommandError(udpErr) {
		return 0, 0, fmt.Errorf("UDP命令执行失败: %v", udpErr)
	}

	// 合并输出
	output := string(tcpOutput) + string(udpOutput)
	if output == "" {
		// 没有数据不是错误，可能是端口没有活动连接
		return 0, 0, nil
	}

	// 解析输出
	var totalSent, totalRecv uint64

	// 使用更可靠的/proc/net/tcp和/proc/net/udp解析网络流量
	// 首先尝试从/proc文件系统读取
	procTcp, err := ioutil.ReadFile("/proc/net/tcp")
	if err != nil {
		pfvLogger.Printf("读取/proc/net/tcp失败: %v", err)
		// 继续执行，尝试其他方法
	} else {
		// 处理TCP连接
		lines := strings.Split(string(procTcp), "\n")
		portHex := fmt.Sprintf("%04X", port) // 转换为16进制

		for _, line := range lines {
			if strings.Contains(line, ":"+portHex) {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					// 第10列是计数器，包括接收和发送计数
					sentRecv := strings.Split(fields[9], ":")
					if len(sentRecv) == 2 {
						sent, err := strconv.ParseUint(sentRecv[0], 16, 64)
						if err != nil {
							pfvLogger.Printf("解析TCP发送计数失败: %v", err)
							continue
						}
						recv, err := strconv.ParseUint(sentRecv[1], 16, 64)
						if err != nil {
							pfvLogger.Printf("解析TCP接收计数失败: %v", err)
							continue
						}
						totalSent += sent
						totalRecv += recv
					}
				}
			}
		}
	}

	// 读取UDP统计
	procUdp, err := ioutil.ReadFile("/proc/net/udp")
	if err != nil {
		pfvLogger.Printf("读取/proc/net/udp失败: %v", err)
		// 继续执行，尝试其他方法
	} else {
		// 处理UDP连接
		lines := strings.Split(string(procUdp), "\n")
		portHex := fmt.Sprintf("%04X", port) // 转换为16进制

		for _, line := range lines {
			if strings.Contains(line, ":"+portHex) {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					// 第10列是计数器，包括接收和发送计数
					sentRecv := strings.Split(fields[9], ":")
					if len(sentRecv) == 2 {
						sent, err := strconv.ParseUint(sentRecv[0], 16, 64)
						if err != nil {
							pfvLogger.Printf("解析UDP发送计数失败: %v", err)
							continue
						}
						recv, err := strconv.ParseUint(sentRecv[1], 16, 64)
						if err != nil {
							pfvLogger.Printf("解析UDP接收计数失败: %v", err)
							continue
						}
						totalSent += sent
						totalRecv += recv
					}
				}
			}
		}
	}

	// 如果/proc系统无法获取数据，回退到netstat分析
	if totalSent == 0 && totalRecv == 0 && output != "" {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, fmt.Sprintf(":%d", port)) {
				// 我们至少知道有连接，但无法获取精确流量
				// 返回一个最小值表示有活动
				totalSent = 1
				totalRecv = 1
			}
		}
	}

	return totalSent, totalRecv, nil
}

// 检查是否需要校准
func checkPfvNeedCalibration() bool {
	_, err := os.Stat(PFV_CALIBRATION_MARKER)
	return os.IsNotExist(err)
}

// 判断命令错误是否为预期错误
func isExpectedCommandError(err error) bool {
	if err == nil {
		return true
	}
	// 检查是否是exec.ExitError类型，且退出状态为1（常见的grep未找到匹配的退出码）
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return true
	}
	// 检查是否是超时错误
	if err == context.DeadlineExceeded {
		return false
	}
	// 其他可能预期的错误
	return strings.Contains(err.Error(), "no such file") ||
		strings.Contains(err.Error(), "executable file not found")
}

// 标记已完成校准
func markPfvCalibrationDone() error {
	// 创建标记文件
	f, err := os.Create(PFV_CALIBRATION_MARKER)
	if err != nil {
		pfvLogger.Printf("创建校准标记文件失败: %v", err)
		return fmt.Errorf("创建校准标记文件失败: %w", err)
	}
	
	// 确保文件被正确关闭
	defer func() {
		if err := f.Close(); err != nil {
			pfvLogger.Printf("关闭校准标记文件失败: %v", err)
		}
	}()
	
	// 写入当前时间作为标记
	_, err = fmt.Fprintf(f, "校准完成时间: %s\n", time.Now().Format(time.RFC3339))
	if err != nil {
		pfvLogger.Printf("写入校准标记文件失败: %v", err)
		return fmt.Errorf("写入校准标记文件失败: %w", err)
	}
	
	// 确保数据写入磁盘
	if err := f.Sync(); err != nil {
		pfvLogger.Printf("同步校准标记文件到磁盘失败: %v", err)
		return fmt.Errorf("同步校准标记文件到磁盘失败: %w", err)
	}
	
	return nil
}

// 校准计数器
func calibratePfvCounters(storage *PfvStorage) {
	pfvLogger.Println("校准计数器...")

	// 复制端口列表以避免并发问题
	var ports []int
	storage.mutex.Lock()
	for port := range storage.Stats {
		ports = append(ports, port)
	}
	storage.mutex.Unlock()

	for _, port := range ports {
		currentSent, currentRecv, err := getPfvPortTraffic(port)
		if err != nil {
			pfvLogger.Printf("端口 %d 校准失败: %v", port, err)
			continue
		}

		// 直接使用mutex原子更新值，避免竞态条件
		storage.mutex.Lock()
		if stats, exists := storage.Stats[port]; exists {
			stats.LastBytesSent = currentSent
			stats.LastBytesRecv = currentRecv
			pfvLogger.Printf("端口 %d 校准完成: 发送=%d, 接收=%d", port, currentSent, currentRecv)
		}
		storage.mutex.Unlock()
	}

	// 标记校准完成
	if err := markPfvCalibrationDone(); err != nil {
		pfvLogger.Printf("标记校准失败: %v", err)
	}
}

// 更新端口统计
func updatePfvPortStats(port int, storage *PfvStorage) {
	// 获取当前状态（使用锁保护）
	storage.mutex.Lock()
	stats, exists := storage.Stats[port]
	if !exists {
		storage.mutex.Unlock()
		pfvLogger.Printf("端口 %d 不在监控列表中", port)
		return
	}

	// 在锁内获取当前值进行比较
	lastBytesSent := stats.LastBytesSent
	lastBytesRecv := stats.LastBytesRecv
	threshold := stats.Threshold
	isBlocked := stats.Blocked
	storage.mutex.Unlock()

	// 获取当前流量（不需要锁保护）
	currentSent, currentRecv, err := getPfvPortTraffic(port)
	if err != nil {
		pfvLogger.Printf("获取端口 %d 流量失败: %v", port, err)
		return
	}

	// 计算增量
	sentDiff := uint64(0)
	recvDiff := uint64(0)
	
	// 确保不会出现负值（防止计数器重置情况）
	if currentSent >= lastBytesSent {
		sentDiff = currentSent - lastBytesSent
	}
	if currentRecv >= lastBytesRecv {
		recvDiff = currentRecv - lastBytesRecv
	}

	// 更新统计（再次使用锁保护）
	storage.mutex.Lock()
	if portStat, ok := storage.Stats[port]; ok { // 再次检查端口是否存在
		portStat.BytesSent += sentDiff
		portStat.BytesReceived += recvDiff
		portStat.LastBytesSent = currentSent
		portStat.LastBytesRecv = currentRecv

		// 检查是否超过阈值
		if threshold > 0 &&
			(portStat.BytesSent+portStat.BytesReceived) > threshold &&
			!isBlocked {
			// 在释放锁后执行阻断操作，避免长时间持有锁
			storage.mutex.Unlock()
			pfvLogger.Printf("端口 %d 流量超过阈值，执行阻断", port)
			if blockPfvPort(port) {
				// 阻断成功后，再次获取锁更新状态
				storage.mutex.Lock()
				if ps, ok := storage.Stats[port]; ok {
					ps.Blocked = true
				}
				storage.mutex.Unlock()
				pfvLogger.Printf("端口 %d 已阻断", port)
			}
			return
		}
	}
	storage.mutex.Unlock()
}

// 定时更新所有端口统计
func startPfvMonitoring(storage *PfvStorage, config *PfvConfig) {
	// 初始化通道
	stopMonitoring = make(chan struct{})
	monitoringStopped = make(chan struct{})

	// 检查是否需要校准
	if checkPfvNeedCalibration() {
		calibratePfvCounters(storage)
	}

	// 定时更新统计
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// 确保函数退出时发送完成信号
	defer close(monitoringStopped)

	for {
		select {
		case <-ticker.C:
			// 复制端口列表以避免并发问题
			var ports []int
			storage.mutex.Lock()
			for port := range storage.Stats {
				ports = append(ports, port)
			}
			storage.mutex.Unlock()

			// 更新每个端口的统计
			for _, port := range ports {
				updatePfvPortStats(port, storage)
			}

			// 保存数据，增加错误重试
			for retries := 0; retries < 3; retries++ {
				if err := storage.SaveToFile(config.DataPath); err != nil {
					pfvLogger.Printf("保存数据失败(%d/3): %v", retries+1, err)
					time.Sleep(100 * time.Millisecond)
				} else {
					break
				}
			}
		case <-stopMonitoring:
			pfvLogger.Println("收到停止监控信号，正在保存最终数据...")
			// 保存最终数据
			if err := storage.SaveToFile(config.DataPath); err != nil {
				pfvLogger.Printf("保存最终数据失败: %v", err)
			}
			return
		}
	}
}

// ===================== 防火墙操作 =====================

// 防火墙操作类型
const (
	FirewallOperationBlock   = "block"   // 阻断操作
	FirewallOperationUnblock = "unblock" // 解除阻断操作
)

// 执行防火墙操作
func executeFirewallOperation(port int, operation string) bool {
	// 验证端口范围
	if port <= 0 || port > 65535 {
		pfvLogger.Printf("无效的端口: %d", port)
		return false
	}

	// 检查防火墙是否运行 - 使用超时控制
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmdCheck := exec.CommandContext(ctx, "systemctl", "is-active", "firewalld")
	output, err := cmdCheck.Output()

	if err != nil || !strings.Contains(string(output), "active") {
		pfvLogger.Printf("防火墙服务未运行或检查出错: %v, 无法操作端口 %d", err, port)
		return false
	}

	// 根据操作类型确定命令参数
	var action string
	var successMsg string
	var failMsg string

	if operation == FirewallOperationBlock {
		action = "--add-rich-rule"
		successMsg = "成功阻断端口 %d (TCP和UDP)"
		failMsg = "阻断%s端口 %d 失败"
	} else if operation == FirewallOperationUnblock {
		action = "--remove-rich-rule"
		successMsg = "成功解除端口 %d 阻断"
		failMsg = "解除%s端口 %d 阻断失败"
	} else {
		pfvLogger.Printf("无效的防火墙操作类型: %s", operation)
		return false
	}

	// 定义规则模板
	ruleTemplate := "rule port port=%d protocol=%s block"
	
	// 执行TCP操作
	tcpCtx, tcpCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer tcpCancel()

	tcpRule := fmt.Sprintf(ruleTemplate, port, "tcp")
	cmdTcp := exec.CommandContext(tcpCtx, "sudo", "firewall-cmd", action, tcpRule)

	// 捕获所有输出以便于日志记录
	tcpOutput := &strings.Builder{}
	cmdTcp.Stdout = tcpOutput
	cmdTcp.Stderr = tcpOutput

	tcpSuccess := true
	if err := cmdTcp.Run(); err != nil {
		pfvLogger.Printf(failMsg+": %v, 输出: %s", "TCP", port, err, tcpOutput.String())
		tcpSuccess = false
		// 如果是阻断操作，失败直接返回
		if operation == FirewallOperationBlock {
			return false
		}
	}

	// 执行UDP操作
	udpCtx, udpCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer udpCancel()

	udpRule := fmt.Sprintf(ruleTemplate, port, "udp")
	cmdUdp := exec.CommandContext(udpCtx, "sudo", "firewall-cmd", action, udpRule)

	// 捕获所有输出以便于日志记录
	udpOutput := &strings.Builder{}
	cmdUdp.Stdout = udpOutput
	cmdUdp.Stderr = udpOutput

	udpSuccess := true
	if err := cmdUdp.Run(); err != nil {
		pfvLogger.Printf(failMsg+": %v, 输出: %s", "UDP", port, err, udpOutput.String())
		udpSuccess = false
		
		// 如果是阻断操作且TCP成功了，需要回滚
		if operation == FirewallOperationBlock && tcpSuccess {
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer rollbackCancel()

			rollbackCmd := exec.CommandContext(rollbackCtx, "sudo", "firewall-cmd", "--remove-rich-rule", tcpRule)

			rollbackOutput := &strings.Builder{}
			rollbackCmd.Stdout = rollbackOutput
			rollbackCmd.Stderr = rollbackOutput

			if rollbackErr := rollbackCmd.Run(); rollbackErr != nil {
				pfvLogger.Printf("回滚 TCP规则失败: %v, 输出: %s", rollbackErr, rollbackOutput.String())
			}
			return false
		}
	}

	// 如果是阻断操作，需要两个协议都成功
	// 如果是解除阻断操作，只要有一个协议成功就算成功
	operationSuccess := false
	if operation == FirewallOperationBlock {
		operationSuccess = tcpSuccess && udpSuccess
	} else {
		operationSuccess = tcpSuccess || udpSuccess
	}

	// 仅当操作成功时才保存配置
	if operationSuccess {
		saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer saveCancel()

		saveCmd := exec.CommandContext(saveCtx, "sudo", "firewall-cmd", "--runtime-to-permanent")
		saveOutput := &strings.Builder{}
		saveCmd.Stdout = saveOutput
		saveCmd.Stderr = saveOutput

		if err := saveCmd.Run(); err != nil {
			pfvLogger.Printf("保存防火墙配置失败: %v, 输出: %s，但规则已临时生效", err, saveOutput.String())
		}
		
		pfvLogger.Printf(successMsg, port)
	}

	return operationSuccess
}

// 阻断端口
func blockPfvPort(port int) bool {
	return executeFirewallOperation(port, FirewallOperationBlock)
}

// 解除端口阻断
func unblockPfvPort(port int) bool {
	return executeFirewallOperation(port, FirewallOperationUnblock)
}

// ===================== API处理 =====================

// API路由处理器
// API安全中间件
func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果是健康检查端点，允许直接访问
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// 从请求头部获取API密钥
		requestKey := r.Header.Get("X-API-Key")
		
		// 如果请求头部没有，尝试从查询参数获取
		if requestKey == "" {
			requestKey = r.URL.Query().Get("api_key")
		}

		// 验证API密钥
		if requestKey == "" || requestKey != apiKey {
			pfvLogger.Printf("无效的API密钥访问尝试: %s", r.RemoteAddr)
			http.Error(w, "未授权的访问", http.StatusUnauthorized)
			return
		}

		// 通过验证，继续处理请求
		next.ServeHTTP(w, r)
	})
}

func setupPfvAPIRoutes(storage *PfvStorage, config *PfvConfig) http.Handler {
	mux := http.NewServeMux()
	
	// 添加健康检查端点
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{\"status\":\"ok\"}")
	})

	// 获取所有端口统计
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := storage.GetAllStats()
		json.NewEncoder(w).Encode(stats)
	})

	// 获取指定端口统计
	mux.HandleFunc("/stats/", func(w http.ResponseWriter, r *http.Request) {
		portStr := strings.TrimPrefix(r.URL.Path, "/stats/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		stats, exists := storage.GetPortStats(port)
		if !exists {
			http.Error(w, "端口未监控", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(stats)
	})

	// 添加端口监控
	mux.HandleFunc("/add/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "仅支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		portStr := strings.TrimPrefix(r.URL.Path, "/add/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		// 获取阈值参数，默认使用全局阈值
		threshold := config.Threshold
		thresholdStr := r.URL.Query().Get("threshold")
		if thresholdStr != "" {
			thresholdVal, err := strconv.ParseUint(thresholdStr, 10, 64)
			if err != nil {
				http.Error(w, "无效的阈值参数", http.StatusBadRequest)
				return
			}
			threshold = thresholdVal
		}

		// 更新端口信息
		storage.UpdatePort(port, threshold)

		// 立即进行一次流量校准
		currentSent, currentRecv, err := getPfvPortTraffic(port)
		if err == nil {
			storage.mutex.Lock()
			if stats, ok := storage.Stats[port]; ok {
				stats.LastBytesSent = currentSent
				stats.LastBytesRecv = currentRecv
			}
			storage.mutex.Unlock()
		}

		// 保存到文件
		if err := storage.SaveToFile(config.DataPath); err != nil {
			pfvLogger.Printf("保存数据失败: %v", err)
			http.Error(w, "保存数据失败", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "端口 %d 已添加到监控，阈值为 %d 字节", port, threshold)
	})

	// 移除端口监控
	mux.HandleFunc("/remove/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "仅支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		portStr := strings.TrimPrefix(r.URL.Path, "/remove/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		// 移除阻断（如果有）
		stats, exists := storage.GetPortStats(port)
		if exists && stats.Blocked {
			if unblockPfvPort(port) {
				storage.SetBlockedStatus(port, false)
			}
		}

		// 移除端口
		if removed := storage.RemovePort(port); !removed {
			http.Error(w, "端口未监控", http.StatusNotFound)
			return
		}

		// 保存到文件
		if err := storage.SaveToFile(config.DataPath); err != nil {
			pfvLogger.Printf("保存数据失败: %v", err)
			http.Error(w, "保存数据失败", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "端口 %d 已从监控移除", port)
	})

	// 重置端口流量
	mux.HandleFunc("/reset/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "仅支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		portStr := strings.TrimPrefix(r.URL.Path, "/reset/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		// 解除阻断（如果有）
		stats, exists := storage.GetPortStats(port)
		if exists && stats.Blocked {
			if unblockPfvPort(port) {
				storage.SetBlockedStatus(port, false)
			}
		}

		// 重置流量
		if reset := storage.ResetPort(port); !reset {
			http.Error(w, "端口未监控", http.StatusNotFound)
			return
		}

		// 保存到文件
		if err := storage.SaveToFile(config.DataPath); err != nil {
			pfvLogger.Printf("保存数据失败: %v", err)
			http.Error(w, "保存数据失败", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "端口 %d 流量已重置", port)
	})

	// 阻断端口处理
	mux.HandleFunc("/block/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "仅支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		portStr := strings.TrimPrefix(r.URL.Path, "/block/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		// 检查端口是否在监控中
		_, exists := storage.GetPortStats(port)
		if !exists {
			http.Error(w, "端口未监控", http.StatusNotFound)
			return
		}

		// 执行阻断
		if !blockPfvPort(port) {
			http.Error(w, "阻断端口失败", http.StatusInternalServerError)
			return
		}

		// 更新状态
		storage.SetBlockedStatus(port, true)

		// 保存到文件
		if err := storage.SaveToFile(config.DataPath); err != nil {
			pfvLogger.Printf("保存数据失败: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "端口 %d 已阻断", port)
	})

	// 解除端口阻断
	mux.HandleFunc("/unblock/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "仅支持POST请求", http.StatusMethodNotAllowed)
			return
		}

		portStr := strings.TrimPrefix(r.URL.Path, "/unblock/")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			http.Error(w, "无效的端口号", http.StatusBadRequest)
			return
		}

		// 检查端口是否在监控中
		_, exists := storage.GetPortStats(port)
		if !exists {
			http.Error(w, "端口未监控", http.StatusNotFound)
			return
		}

		// 执行解除阻断
		if !unblockPfvPort(port) {
			http.Error(w, "解除阻断失败", http.StatusInternalServerError)
			return
		}

		// 更新状态
		storage.SetBlockedStatus(port, false)

		// 保存到文件
		if err := storage.SaveToFile(config.DataPath); err != nil {
			pfvLogger.Printf("保存数据失败: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "端口 %d 已解除阻断", port)
	})

	return apiKeyMiddleware(mux)
}

// 启动API服务
func startPfvAPIServer(storage *PfvStorage, config *PfvConfig) {
	apiKey = PFV_DEFAULT_API_KEY
	addr := fmt.Sprintf(":%d", config.ApiPort)
	server := &http.Server{
		Addr:         addr,
		Handler:      setupPfvAPIRoutes(storage, config),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 设置优雅关闭
	idleConnsClosed := make(chan struct{})
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
		<-sigc

		// 收到信号后停止接收新的连接
		pfvLogger.Println("正在关闭系统...")

		// 先停止监控协程
		pfvLogger.Println("停止监控协程...")
		close(stopMonitoring)
		<-monitoringStopped
		pfvLogger.Println("监控协程已停止")

		// 实际关闭API服务
		pfvLogger.Println("关闭API服务...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			pfvLogger.Printf("API服务关闭出错: %v", err)
		}

		// 保存最后的状态
		pfvLogger.Println("保存最终状态...")
		for retries := 0; retries < 3; retries++ {
			if err := storage.SaveToFile(config.DataPath); err != nil {
				pfvLogger.Printf("保存最终数据失败(%d/3): %v", retries+1, err)
				time.Sleep(100 * time.Millisecond)
			} else {
				pfvLogger.Println("最终状态保存成功")
				break
			}
		}

		close(idleConnsClosed)
	}()

	pfvLogger.Printf("启动API服务，监听地址: %s", addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		pfvLogger.Fatalf("API服务启动失败: %v", err)
	}

	<-idleConnsClosed
	pfvLogger.Println("API服务已经完全关闭")
}

// ===================== 全局变量 =====================

// 程序全局状态变量
var (
	// 日志对象
	pfvLogger *log.Logger

	// API安全相关
	apiKey string

	// 用于停止监控的通道
	stopMonitoring    chan struct{}
	monitoringStopped chan struct{}
)

// ===================== 主程序 =====================

// 主程序
func pfvMain() {
	// 命令行参数
	configPath := flag.String("config", "/etc/pfv/pfv.conf", "配置文件路径")
	logPath := flag.String("log", "", "日志文件路径")
	flag.Parse()

	// 初始化日志记录器
	logFile := "/var/log/pfv/pfv.log"
	// 优先使用命令行参数，其次使用环境变量
	if *logPath != "" {
		logFile = *logPath
	} else if os.Getenv("PFV_LOG") != "" {
		logFile = os.Getenv("PFV_LOG")
	}

	// 确保日志目录存在
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("创建日志目录失败: %v\n", err)
		os.Exit(1)
	}

	// 打开日志文件
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// 设置日志
	pfvLogger = log.New(f, "", log.LstdFlags)
	pfvLogger.Printf("PFV 端口流量监控工具启动 (版本 %s)", PFV_VERSION)

	// 加载配置
	config, err := loadPfvConfig(*configPath)
	if err != nil {
		pfvLogger.Fatalf("加载配置失败: %v", err)
	}
	pfvLogger.Printf("配置加载完成: API端口=%d, 日志=%s, 数据=%s",
		config.ApiPort, config.LogPath, config.DataPath)

	// 初始化存储
	storage := NewPfvStorage()

	// 加载已有数据
	if err := storage.LoadFromFile(config.DataPath); err != nil {
		pfvLogger.Printf("加载数据失败: %v, 将使用空数据", err)
	} else {
		pfvLogger.Printf("已加载 %d 个端口的统计数据", len(storage.Stats))
	}

	// 初始配置同步
	for _, port := range config.Ports {
		if _, exists := storage.GetPortStats(port); !exists {
			storage.UpdatePort(port, config.Threshold)
			pfvLogger.Printf("添加端口监控: %d, 阈值: %d", port, config.Threshold)
		}
	}

	// 保存初始数据
	if err := storage.SaveToFile(config.DataPath); err != nil {
		pfvLogger.Printf("保存初始数据失败: %v", err)
	}

	// 启动监控协程
	go startPfvMonitoring(storage, config)

	// 启动API服务（阻塞）
	startPfvAPIServer(storage, config)
}

// 程序入口点
func main() {
	// 调用主程序函数
	pfvMain()
}
