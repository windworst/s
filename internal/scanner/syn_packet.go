package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"s/internal/utils"

	"golang.org/x/net/ipv4"
)

const (
	tcpHeaderSize = 20
	ipHeaderSize  = 20
)

// TCPHeader TCP头部结构
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgPtr     uint16
}

// SYN扫描需要root/管理员权限
func checkPrivileges() error {
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return fmt.Errorf("SYN scan requires root privileges")
	}
	return nil
}

func (s *Scanner) startSYNScan() {
	// 检查权限
	if err := checkPrivileges(); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 解析IP范围
	ips, err := utils.ParseIPRange(s.config.StartIP, s.config.EndIP)
	if err != nil {
		fmt.Printf("Error parsing IP range: %v\n", err)
		return
	}

	// 解析端口范围
	ports, err := utils.ParsePorts(s.config.Ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		return
	}

	// 创建原始套接字
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error creating raw socket: %v\n", err)
		return
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		fmt.Printf("Error creating raw connection: %v\n", err)
		return
	}

	// 创建工作任务通道
	tasks := make(chan scanTask, len(ips)*len(ports))
	results := make(chan ScanResult, len(ips)*len(ports))

	// 启动工作协程
	for i := 0; i < s.config.Threads; i++ {
		s.workerWg.Add(1)
		go s.synWorker(rawConn, tasks, results)
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

	// 启动结果处理
	var completed int
	total := len(ips) * len(ports)

	for result := range results {
		completed++
		if result.IsOpen {
			s.AddResult(result)
			fmt.Printf("%s:%d\n", result.IP, result.Port)
		}

		if completed == total {
			close(results)
			break
		}
	}
}

func (s *Scanner) synWorker(conn *ipv4.RawConn, tasks <-chan scanTask, results chan<- ScanResult) {
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

			// 构造SYN包
			header := &ipv4.Header{
				Version:  4,
				Len:      ipHeaderSize,
				TOS:      0,
				TotalLen: ipHeaderSize + tcpHeaderSize,
				TTL:      64,
				Protocol: 6, // TCP
				Dst:      net.ParseIP(task.ip),
			}

			// 构造TCP头
			tcpHeader := &TCPHeader{
				SrcPort:    uint16(1024 + (time.Now().UnixNano() % 64511)), // 随机源端口
				DstPort:    uint16(task.port),
				SeqNum:     uint32(time.Now().UnixNano()),
				DataOffset: 5,
				Flags:      0x02, // SYN
				Window:     64240,
			}

			// 发送SYN包并等待响应
			if err := s.sendSYNPacket(conn, header, tcpHeader); err == nil {
				// 等待响应
				if response, err := s.receiveSYNACK(conn, tcpHeader.SrcPort, uint16(task.port), time.Duration(s.config.Timeout)*time.Second); err == nil {
					result.IsOpen = (response.Flags & 0x12) == 0x12 // SYN+ACK
				}
			}

			results <- result
		}
	}
}

// 计算TCP校验和
func tcpChecksum(header *TCPHeader, srcIP, dstIP net.IP) uint16 {
	// TCP伪首部
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP协议号
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(tcpHeaderSize))

	// TCP头部
	tcpBytes := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcpBytes[0:2], header.SrcPort)
	binary.BigEndian.PutUint16(tcpBytes[2:4], header.DstPort)
	binary.BigEndian.PutUint32(tcpBytes[4:8], header.SeqNum)
	binary.BigEndian.PutUint32(tcpBytes[8:12], header.AckNum)
	tcpBytes[12] = header.DataOffset << 4
	tcpBytes[13] = header.Flags
	binary.BigEndian.PutUint16(tcpBytes[14:16], header.Window)
	binary.BigEndian.PutUint16(tcpBytes[16:18], 0) // 校验和先设为0
	binary.BigEndian.PutUint16(tcpBytes[18:20], header.UrgPtr)

	// 计算校验和
	var sum uint32
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i:]))
	}
	for i := 0; i < len(tcpBytes); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpBytes[i:]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

func (s *Scanner) sendSYNPacket(conn *ipv4.RawConn, header *ipv4.Header, tcpHeader *TCPHeader) error {
	// 获取本地IP地址
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("failed to get interface addresses: %v", err)
	}

	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				srcIP = ipv4
				break
			}
		}
	}

	if srcIP == nil {
		return fmt.Errorf("no suitable source IP address found")
	}

	// 设置IP头部
	header.Src = srcIP
	header.ID = int(time.Now().UnixNano() & 0xffff)

	// 计算TCP校验和
	tcpHeader.Checksum = tcpChecksum(tcpHeader, srcIP, header.Dst)

	// 序列化TCP头部
	tcpBytes := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcpBytes[0:2], tcpHeader.SrcPort)
	binary.BigEndian.PutUint16(tcpBytes[2:4], tcpHeader.DstPort)
	binary.BigEndian.PutUint32(tcpBytes[4:8], tcpHeader.SeqNum)
	binary.BigEndian.PutUint32(tcpBytes[8:12], tcpHeader.AckNum)
	tcpBytes[12] = tcpHeader.DataOffset << 4
	tcpBytes[13] = tcpHeader.Flags
	binary.BigEndian.PutUint16(tcpBytes[14:16], tcpHeader.Window)
	binary.BigEndian.PutUint16(tcpBytes[16:18], tcpHeader.Checksum)
	binary.BigEndian.PutUint16(tcpBytes[18:20], tcpHeader.UrgPtr)

	// 发送数据包
	return conn.WriteTo(header, tcpBytes, nil)
}

func (s *Scanner) receiveSYNACK(conn *ipv4.RawConn, srcPort, dstPort uint16, timeout time.Duration) (*TCPHeader, error) {
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)

	buf := make([]byte, 1500) // MTU大小
	for time.Now().Before(deadline) {
		header, payload, _, err := conn.ReadFrom(buf)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				return nil, fmt.Errorf("timeout waiting for response")
			}
			continue
		}

		if header == nil || len(payload) < tcpHeaderSize {
			continue
		}

		// 解析TCP头部
		tcpHeader := &TCPHeader{
			SrcPort:    binary.BigEndian.Uint16(payload[0:2]),
			DstPort:    binary.BigEndian.Uint16(payload[2:4]),
			SeqNum:     binary.BigEndian.Uint32(payload[4:8]),
			AckNum:     binary.BigEndian.Uint32(payload[8:12]),
			DataOffset: payload[12] >> 4,
			Flags:      payload[13],
			Window:     binary.BigEndian.Uint16(payload[14:16]),
			Checksum:   binary.BigEndian.Uint16(payload[16:18]),
			UrgPtr:     binary.BigEndian.Uint16(payload[18:20]),
		}

		// 检查是否是我们期望的响应
		if tcpHeader.DstPort == srcPort && tcpHeader.SrcPort == dstPort {
			return tcpHeader, nil
		}
	}

	return nil, fmt.Errorf("no response received")
}
