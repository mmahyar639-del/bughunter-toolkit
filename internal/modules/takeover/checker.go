package takeover

import (
	"strings"
	"sync"

	"github.com/mmahyar639-del/bughunter-toolkit/internal/core"
)

func ConfirmTakeover(results []ResolveResult) []ResolveResult {
	var confirmed []ResolveResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := core.NewHTTPClient()

	for i := range results {
		res := &results[i]
		if !res.IsVulnerable {
			continue
		}

		wg.Add(1)
		go func(r *ResolveResult) {
			defer wg.Done()

			var targetFP Fingerprint
			for _, fp := range Database {
				if fp.Service == r.Service {
					targetFP = fp
					break
				}
			}
			if targetFP.Service == "" {
				return
			}

			// تلاش اول: HTTP
			body, err := client.Get("http://" + r.Subdomain)
			if err != nil {
				// تلاش دوم (Fallback): HTTPS (برخی سرویس‌ها فقط HTTPS دارند)
				body, err = client.Get("https://" + r.Subdomain)
				if err != nil {
					return
				}
			}

			bodyLower := strings.ToLower(string(body))
			matchLower := strings.ToLower(targetFP.BodyMatch)

			if strings.Contains(bodyLower, matchLower) {
				mu.Lock()
				r.IsConfirmed = true
				confirmed = append(confirmed, *r)
				mu.Unlock()
			}
		}(res)
	}

	wg.Wait()
	return confirmed
}