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
	if runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("SYN Scan Requires Root/Administrator Privileges")
	}
	return nil
}

func (s *Scanner) startSYNScan() {
	if err := checkPrivileges(); err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	ips, err := utils.ParseIPRange(s.config.StartIP, s.config.EndIP)
	if err != nil {
		fmt.Printf("Invalid Hosts To Scan\n")
		return
	}

	ports, err := utils.ParsePorts(s.config.Ports)
	if err != nil {
		fmt.Printf("Invalid Port List\n")
		return
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Fail To Create Listen Socket : %v\n", err)
		return
	}
	defer conn.Close()

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		fmt.Printf("Fail To Create Socket : %v\n", err)
		return
	}

	// 启动接收响应的goroutine
	s.workerWg.Add(1)
	go func() {
		defer s.workerWg.Done()
		for {
			select {
			case <-s.stopChan:
				return
			default:
				response, ip, port, err := s.receiveSYNACK(rawConn, time.Duration(s.config.Timeout)*time.Second)
				if err == nil && response != nil && (response.Flags&0x12) == 0x12 {
					result := ScanResult{
						IP:        ip,
						Port:      int(port),
						IsOpen:    true,
						Timestamp: time.Now(),
					}
					s.AddResult(result)
					fmt.Printf("%-16s %-5d Open             \n", ip, port)
				}
			}
		}
	}()

	// 发送SYN包
	var scanned int
	var lastIP string
	var lastPort int

	for _, ip := range ips {
		for _, port := range ports {
			select {
			case <-s.stopChan:
				return
			default:
				lastIP = ip.String()
				lastPort = port

				header := &ipv4.Header{
					Version:  4,
					Len:      ipHeaderSize,
					TOS:      0,
					TotalLen: ipHeaderSize + tcpHeaderSize,
					TTL:      64,
					Protocol: 6,
					Dst:      net.ParseIP(ip.String()),
				}

				tcpHeader := &TCPHeader{
					SrcPort:    uint16(1024 + (time.Now().UnixNano() % 64511)),
					DstPort:    uint16(port),
					SeqNum:     uint32(time.Now().UnixNano()),
					DataOffset: 5,
					Flags:      0x02,
					Window:     64240,
				}

				s.sendSYNPacket(rawConn, header, tcpHeader)
				scanned++
				fmt.Printf("%d Ports Scanned.              \r", scanned)
			}
		}
	}

	fmt.Printf("Last Scan: %s:%d                \n", lastIP, lastPort)

	// 等待最后的响应
	time.Sleep(time.Duration(s.config.Timeout) * time.Second)
	if s.config.SaveResults {
		s.SaveResults()
	}
}

func (s *Scanner) receiveSYNACK(conn *ipv4.RawConn, timeout time.Duration) (*TCPHeader, string, uint16, error) {
	buf := make([]byte, 1500) // MTU大小

	// 设置读取超时
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)

	for {
		header, payload, _, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, "", 0, err
			}
			return nil, "", 0, err
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

		return tcpHeader, header.Src.String(), tcpHeader.SrcPort, nil
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
		return err
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
		return err
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
