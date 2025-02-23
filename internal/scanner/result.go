package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveResults 将扫描结果保存到文件
func (s *Scanner) SaveResults() error {
	// 创建结果目录
	resultDir := "results"
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %v", err)
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(resultDir, fmt.Sprintf("scan_%s.txt", timestamp))

	// 创建文件
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create result file: %v", err)
	}
	defer file.Close()

	// 写入扫描信息
	fmt.Fprintf(file, "Scan Report\n")
	fmt.Fprintf(file, "===========\n\n")
	fmt.Fprintf(file, "Scan Type: %s\n", s.config.ScanType)
	fmt.Fprintf(file, "Start IP: %s\n", s.config.StartIP)
	if s.config.EndIP != "" {
		fmt.Fprintf(file, "End IP: %s\n", s.config.EndIP)
	}
	fmt.Fprintf(file, "Ports: %s\n", s.config.Ports)
	fmt.Fprintf(file, "Threads: %d\n", s.config.Threads)
	fmt.Fprintf(file, "Timeout: %d seconds\n", s.config.Timeout)
	fmt.Fprintf(file, "Banner: %v\n", s.config.GetBanner)
	fmt.Fprintf(file, "HTTP Banner: %v\n", s.config.HTTPBanner)
	fmt.Fprintf(file, "\nOpen Ports:\n")
	fmt.Fprintf(file, "===========\n\n")

	// 写入扫描结果
	for _, result := range s.results {
		if result.Banner != "" {
			fmt.Fprintf(file, "%s:%d - %s\n", result.IP, result.Port, result.Banner)
		} else {
			fmt.Fprintf(file, "%s:%d\n", result.IP, result.Port)
		}
	}

	// 同时保存JSON格式的结果
	jsonFilename := filepath.Join(resultDir, fmt.Sprintf("scan_%s.json", timestamp))
	jsonFile, err := os.Create(jsonFilename)
	if err != nil {
		return fmt.Errorf("failed to create JSON result file: %v", err)
	}
	defer jsonFile.Close()

	// 创建JSON格式的报告
	report := struct {
		Config  *Config      `json:"config"`
		Results []ScanResult `json:"results"`
	}{
		Config:  s.config,
		Results: s.results,
	}

	// 写入JSON
	encoder := json.NewEncoder(jsonFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to write JSON report: %v", err)
	}

	fmt.Printf("Results saved to:\n%s\n%s\n", filename, jsonFilename)
	return nil
}
