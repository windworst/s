package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPRange 解析IP范围
// 支持以下格式:
// - 单个IP: 192.168.1.1
// - IP范围: 192.168.1.1 192.168.1.254
// - CIDR: 192.168.1.0/24
func ParseIPRange(startIP, endIP string) ([]net.IP, error) {
	// 检查是否是CIDR格式
	if strings.Contains(startIP, "/") {
		_, ipnet, err := net.ParseCIDR(startIP)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR format: %v", err)
		}
		return expandCIDR(ipnet), nil
	}

	// 解析起始IP
	start := net.ParseIP(startIP)
	if start == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startIP)
	}

	// 如果没有结束IP，则只扫描单个IP
	if endIP == "" {
		return []net.IP{start}, nil
	}

	// 解析结束IP
	end := net.ParseIP(endIP)
	if end == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endIP)
	}

	return expandIPRange(start, end), nil
}

// expandCIDR 展开CIDR范围内的所有IP
func expandCIDR(ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, cloneIP(ip))
	}
	return ips
}

// expandIPRange 展开IP范围内的所有IP
func expandIPRange(start, end net.IP) []net.IP {
	var ips []net.IP
	for ip := cloneIP(start); !ip.Equal(incrementIP(cloneIP(end))); incrementIP(ip) {
		ips = append(ips, cloneIP(ip))
	}
	return ips
}

// cloneIP 克隆IP地址
func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// incrementIP 将IP地址加1
func incrementIP(ip net.IP) net.IP {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
	return ip
}

// ParsePorts 解析端口范围
// 支持以下格式:
// - 单个端口: 80
// - 端口范围: 1-65535
// - 端口列表: 21,80,443,3389
func ParsePorts(portsStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portsStr, ",")

	for _, part := range parts {
		if strings.Contains(part, "-") {
			// 处理端口范围
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}

			ports = append(ports, port)
		}
	}

	return ports, nil
}
