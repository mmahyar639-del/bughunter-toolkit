package takeover

import (
	"bufio"
	"os"
	"strings"
)

// ReadSubdomainsFromFile لیست ساب‌دامین‌ها را از یک فایل متنی می‌خواند
func ReadSubdomainsFromFile(filePath string) ([]string, error) {
	// باز کردن فایل
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close() // مطمئن شویم فایل در انتها بسته می‌شود

	var subdomains []string
	scanner := bufio.NewScanner(file)

	// خواندن خط به خط
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// نادیده گرفتن خطوط خالی یا کامنت‌ها
		if line != "" && !strings.HasPrefix(line, "#") {
			subdomains = append(subdomains, line)
		}
	}

	// بررسی خطای احتمالی در حین اسکن
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}