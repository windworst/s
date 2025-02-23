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
}

// NewScanner 创建新的扫描器实例
func NewScanner(config *Config) (*Scanner, error) {
	// 验证IP地址格式
	if net.ParseIP(config.StartIP) == nil {
		return nil, fmt.Errorf("invalid start IP address: %s", config.StartIP)
	}
	if config.EndIP != "" && net.ParseIP(config.EndIP) == nil {
		return nil, fmt.Errorf("invalid end IP address: %s", config.EndIP)
	}

	return &Scanner{
		config:   config,
		results:  make([]ScanResult, 0),
		stopChan: make(chan struct{}),
	}, nil
}

// Start 开始扫描
func (s *Scanner) Start() {
	if s.config.ScanType == "TCP" {
		s.startTCPScan()
	} else {
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
