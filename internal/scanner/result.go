package scanner

import (
	"fmt"
	"os"
)

// SaveResults 将扫描结果保存到文件
func (s *Scanner) SaveResults() error {
	// 使用固定的文件名
	filename := "Result.txt"

	// 创建文件
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to create result file: %v", err)
	}
	defer file.Close()

	// 写入扫描结果
	for _, result := range s.results {
		if result.Banner != "" {
			fmt.Fprintf(file, "%s:%d -> %s\n", result.IP, result.Port, result.Banner)
		} else {
			fmt.Fprintf(file, "%s:%d\n", result.IP, result.Port)
		}
	}

	return nil
}
