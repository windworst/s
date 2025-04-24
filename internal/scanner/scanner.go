package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Config 扫描器配置
type Config struct {
	ScanType    string // TCP 或 SYN
	StartIP     string
	EndIP       string
	Ports       string
	Threads     int
	Timeout     int
	SaveResults bool
	GetBanner   bool
	HTTPBanner  bool
}

// Scanner 扫描器接口
type Scanner struct {
	config   *Config
	results  []ScanResult
	mutex    sync.Mutex
	stopChan chan struct{}
	workerWg sync.WaitGroup
}

// ScanResult 扫描结果
type ScanResult struct {
	IP        string
	Port      int
	IsOpen    bool
	Banner    string
	Timestamp time.Time
	Error     string // 存储扫描过程中的错误信息
}

// NewScanner 创建新的扫描器实例
func NewScanner(config *Config) (*Scanner, error) {
	if config.ScanType != "TCP" && config.ScanType != "SYN" {
		return nil, fmt.Errorf("Invalid Scan Type\n")
	}

	// 验证起始 IP 或 CIDR 格式
	if !isValidIPOrCIDR(config.StartIP) {
		return nil, fmt.Errorf("Invalid Hosts To Scan\n")
	}

	// 如果有 EndIP，则也检查
	if config.EndIP != "" && net.ParseIP(config.EndIP) == nil {
		return nil, fmt.Errorf("Invalid Hosts To Scan\n")
	}

	return &Scanner{
		config:   config,
		results:  make([]ScanResult, 0),
		stopChan: make(chan struct{}),
	}, nil
}

func isValidIPOrCIDR(input string) bool {
	if strings.Contains(input, "/") {
		_, _, err := net.ParseCIDR(input)
		return err == nil
	}
	return net.ParseIP(input) != nil
}

// Start 开始扫描
func (s *Scanner) Start() {
	fmt.Printf("TCP Port Scanner V1.2 By WinEggDrop\n\n")

	if s.config.ScanType == "TCP" {
		fmt.Printf("Normal Scan: About To Scan %s Using %d Threads\n", s.config.StartIP, s.config.Threads)
		s.startTCPScan()
	} else {
		fmt.Printf("SYN Scan: About To Scan %s Using %d Thread\n", s.config.StartIP, s.config.Threads)
		s.startSYNScan()
	}
}

// Stop 停止扫描
func (s *Scanner) Stop() {
	close(s.stopChan)
	s.workerWg.Wait()
}

// AddResult 添加扫描结果
func (s *Scanner) AddResult(result ScanResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = append(s.results, result)
}
