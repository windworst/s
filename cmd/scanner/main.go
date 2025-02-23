package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"s/internal/scanner"
)

func printHelp() {
	appName := os.Args[0]
	fmt.Printf("Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12/24 80 512\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 1-65535 512\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 12.12.12.254 21,3389,5631 512\n", appName)
	fmt.Printf("Example: %s TCP 12.12.12.12 21,3389,5631 512\n", appName)
	fmt.Printf("Example: %s SYN 12.12.12.12 12.12.12.254 80\n", appName)
	fmt.Printf("Example: %s SYN 12.12.12.12 1-65535\n", appName)
	fmt.Printf("Example: %s SYN 12.12.12.12 12.12.12.254 21,80,3389\n", appName)
	fmt.Printf("Example: %s SYN 12.12.12.12 21,80,3389\n", appName)
}

func main() {
	if len(os.Args) < 4 {
		printHelp()
		os.Exit(1)
	}

	// 解析基本参数
	scanType := strings.ToUpper(os.Args[1])
	if scanType != "TCP" && scanType != "SYN" {
		fmt.Println("Error: scan type must be TCP or SYN")
		os.Exit(1)
	}

	// 创建扫描配置
	config := &scanner.Config{
		ScanType:    scanType,
		StartIP:     os.Args[2],
		Ports:       "",
		Threads:     512, // 默认线程数
		Timeout:     3,   // 默认超时3秒
		SaveResults: false,
		GetBanner:   false,
		HTTPBanner:  false,
	}

	// 解析IP和端口参数
	args := os.Args[3:]
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// 处理选项参数
		if strings.HasPrefix(arg, "/") {
			switch strings.ToUpper(arg) {
			case "/SAVE":
				config.SaveResults = true
			case "/BANNER":
				config.GetBanner = true
			case "/HBANNER":
				config.GetBanner = true
				config.HTTPBanner = true
			default:
				if strings.HasPrefix(strings.ToUpper(arg), "/T") {
					if timeout := strings.TrimPrefix(strings.ToUpper(arg), "/T"); timeout != "" {
						fmt.Sscanf(timeout, "%d", &config.Timeout)
					}
				}
			}
			continue
		}

		// 处理IP和端口参数
		if config.EndIP == "" && strings.Contains(arg, ".") {
			config.EndIP = arg
			continue
		}
		if config.Ports == "" {
			config.Ports = arg
			continue
		}
		if t, err := fmt.Sscanf(arg, "%d", &config.Threads); err == nil && t > 0 {
			continue
		}
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		os.Exit(0)
	}()

	// 创建并启动扫描器
	s, err := scanner.NewScanner(config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	s.Start()
}
