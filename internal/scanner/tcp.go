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
		fmt.Printf("Invalid Hosts To Scan\n")
		return
	}

	// 解析端口范围
	ports, err := utils.ParsePorts(s.config.Ports)
	if err != nil {
		fmt.Printf("Invalid Port List\n")
		return
	}

	// 创建任务通道，只缓存正在处理的任务
	tasks := make(chan scanTask, s.config.Threads)
	results := make(chan ScanResult)

	// 启动工作线程池
	var wg sync.WaitGroup
	for i := 0; i < s.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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

					select {
					case <-s.stopChan:
						return
					case results <- result:
					}
				}
			}
		}()
	}

	// 启动结果处理
	var completed int
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range results {
			if result.IsOpen {
				s.AddResult(result)
				if result.Banner != "" {
					fmt.Printf("%-16s %-5d -> \"%s\"           \n", result.IP, result.Port, result.Banner)
				} else {
					fmt.Printf("%-16s %-5d Open             \n", result.IP, result.Port)
				}
			}
			completed++
			fmt.Printf("%d Ports Scanned.Taking %d Threads \r", completed, s.config.Threads)
		}
	}()

	// 分配扫描任务
	totalTasks := len(ips) * len(ports)
	taskCount := 0
	for _, ip := range ips {
		for _, port := range ports {
			select {
			case <-s.stopChan:
				close(tasks)
				wg.Wait()
				close(results)
				resultWg.Wait()
				return
			case tasks <- scanTask{ip: ip.String(), port: port}:
				taskCount++
				if taskCount == totalTasks {
					close(tasks)
				}
			}
		}
	}

	// 等待所有工作完成
	wg.Wait()
	close(results)
	resultWg.Wait()

	// 保存结果
	if s.config.SaveResults {
		s.SaveResults()
	}
}

type scanTask struct {
	ip   string
	port int
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
