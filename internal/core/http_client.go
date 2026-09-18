package core

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
)

// HTTPClient یک کلاینت HTTP مقاوم با قابلیت تلاش مجدد است
type HTTPClient struct {
	client *retryablehttp.Client
}

// NewHTTPClient یک نمونه جدید از کلاینت HTTP را با تنظیمات بهینه برای باگ بانتی می‌سازد
func NewHTTPClient() *HTTPClient {
	// تنظیمات پیش‌فرض برای درخواست‌های تکی (Single)
	options := retryablehttp.DefaultOptionsSingle
	options.Timeout = 10 * time.Second       // حداکثر زمان انتظار برای هر درخواست
	options.RetryMax = 3                     // حداکثر تعداد تلاش مجدد در صورت شکست
	options.RetryWaitMin = 1 * time.Second   // حداقل زمان انتظار بین تلاش‌ها
	options.RetryWaitMax = 3 * time.Second   // حداکثر زمان انتظار بین تلاش‌ها

	client := retryablehttp.NewClient(options)

	// تنظیم یک User-Agent استاندارد برای جلوگیری از بلاک شدن اولیه توسط WAFها
	client.HTTPClient.Transport = &http.Transport{
		// در فازهای بعدی می‌توانیم fastdialer را به اینجا اضافه کنیم
	}

	return &HTTPClient{client: client}
}

// Get یک درخواست GET ارسال کرده و بدنه پاسخ را به صورت بایت برمی‌گرداند
func (c *HTTPClient) Get(url string) ([]byte, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("درخواست ناموفق بود: %w", err)
	}
	defer resp.Body.Close()

	// بررسی کد وضعیت (فقط کدهای 2xx موفق در نظر گرفته می‌شوند)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("کد وضعیت غیرمنتظره: %d", resp.StatusCode)
	}

	// خواندن کامل بدنه پاسخ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("خطا در خواندن بدنه پاسخ: %w", err)
	}

	return body, nil
}