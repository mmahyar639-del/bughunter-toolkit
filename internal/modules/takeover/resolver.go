package takeover

import (
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

type ResolveResult struct {
	Subdomain    string
	IsVulnerable bool
	IsConfirmed  bool
	Service      string
	CNAMEs       []string
	IPs          []string
	Error        error
}

func CheckSubdomains(subdomains []string) []ResolveResult {
	var results []ResolveResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	options := fastdialer.DefaultOptions
	options.DialerTimeout = 3 * time.Second // تایم‌اوت سریع‌تر برای پردازش دسته‌ای

	dialer, err := fastdialer.NewDialer(options)
	if err != nil {
		return results
	}
	defer dialer.Close()

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			
			result := ResolveResult{Subdomain: subdomain}
			dnsData, err := dialer.GetDNSData(subdomain)
			if err != nil {
				mu.Lock()
				result.Error = err
				results = append(results, result)
				mu.Unlock()
				return
			}

			result.IPs = dnsData.A
			result.CNAMEs = dnsData.CNAME

			for _, cname := range dnsData.CNAME {
				for _, fp := range Database {
					for _, match := range fp.CNAMEMatch {
						if strings.Contains(strings.ToLower(cname), strings.ToLower(match)) {
							result.IsVulnerable = true
							result.Service = fp.Service
							break
						}
					}
					if result.IsVulnerable {
						break
					}
				}
				if result.IsVulnerable {
					break
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	return results
}