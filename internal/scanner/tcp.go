package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"s/internal/utils"
)

// startTCPScan 实现TCP扫描
func (s *Scanner) startTCPScan() {
	// 解析IP范围
	ips, err := utils.ParseIPRange(s.config.StartIP, s.config.EndIP)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 解析端口范围
	ports, err := utils.ParsePorts(s.config.Ports)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 创建工作任务通道
	tasks := make(chan scanTask, len(ips)*len(ports))
	results := make(chan ScanResult, len(ips)*len(ports))

	// 启动工作协程
	for i := 0; i < s.config.Threads; i++ {
		s.workerWg.Add(1)
		go s.tcpWorker(tasks, results)
	}

	// 发送扫描任务
	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case <-s.stopChan:
					return
				case tasks <- scanTask{ip: ip.String(), port: port}:
				}
			}
		}
		close(tasks)
	}()

	// 启动结果处理协程
	var resultWg sync.WaitGroup
	resultWg.Add(1)

	go func() {
		defer resultWg.Done()
		for result := range results {
			if result.IsOpen {
				s.AddResult(result)
				if result.Banner != "" {
					fmt.Printf("%s:%d - %s\n", result.IP, result.Port, result.Banner)
				} else {
					fmt.Printf("%s:%d\n", result.IP, result.Port)
				}
			}
		}
	}()

	// 等待所有工作完成
	s.workerWg.Wait()
	close(results)
	resultWg.Wait()

	// 保存结果
	if s.config.SaveResults {
		if err := s.SaveResults(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

type scanTask struct {
	ip   string
	port int
}

func (s *Scanner) tcpWorker(tasks <-chan scanTask, results chan<- ScanResult) {
	defer s.workerWg.Done()

	for task := range tasks {
		select {
		case <-s.stopChan:
			return
		default:
			result := ScanResult{
				IP:        task.ip,
				Port:      task.port,
				IsOpen:    false,
				Timestamp: time.Now(),
			}

			// 尝试建立TCP连接
			addr := fmt.Sprintf("%s:%d", task.ip, task.port)
			conn, err := net.DialTimeout("tcp", addr, time.Duration(s.config.Timeout)*time.Second)

			if err == nil {
				result.IsOpen = true

				// 获取Banner
				if s.config.GetBanner {
					if s.config.HTTPBanner && (task.port == 80 || task.port == 443) {
						result.Banner = s.getHTTPBanner(conn)
					} else {
						result.Banner = s.getBanner(conn)
					}
				}

				conn.Close()
			}

			results <- result
		}
	}
}

// getBanner 获取服务Banner
func (s *Scanner) getBanner(conn net.Conn) string {
	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))

	// 读取Banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// getHTTPBanner 获取HTTP服务Banner
func (s *Scanner) getHTTPBanner(conn net.Conn) string {
	// 发送HTTP HEAD请求
	httpReq := "HEAD / HTTP/1.0\r\n\r\n"
	conn.Write([]byte(httpReq))

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))

	// 读取响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	response := string(buffer[:n])

	// 提取Server头
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
	}

	return ""
}
