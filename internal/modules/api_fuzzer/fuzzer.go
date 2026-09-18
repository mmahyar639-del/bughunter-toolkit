package api_fuzzer

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mmahyar639-del/bughunter-toolkit/internal/core"
)

type FuzzResult struct {
	URL          string
	ParamName    string
	Payload      string
	IsSuspicious bool
	Reason       string
}

// RunFuzzerBatch لیستی از URLها را به صورت همزمان اما با رعایت فاصله زمانی (Rate Limit) فاز می‌کند
func RunFuzzerBatch(targetURLs []string) []FuzzResult {
	var results []FuzzResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	httpClient := core.NewHTTPClient()

	for _, targetURL := range targetURLs {
		params := AnalyzeURL(targetURL)
		if len(params) == 0 {
			continue
		}

		// دریافت پاسخ پایه برای مقایسه
		baseResp, err := httpClient.Get(targetURL)
		baseLength := 0
		if err == nil {
			baseLength = len(baseResp)
		}

		for _, param := range params {
			payloadGroups := GetSmartPayloads(param.Type)

			for _, group := range payloadGroups {
				for _, payload := range group.Payloads {
					
					mutatedURL, err := MutateURL(targetURL, param, payload)
					if err != nil {
						continue
					}

					wg.Add(1)
					go func(mURL string, pName string, pld string) {
						defer wg.Done()

						// Rate Limiting: تاخیر کوچک برای جلوگیری از بن شدن توسط WAF
						time.Sleep(150 * time.Millisecond)

						respBody, err := httpClient.Get(mURL)
						if err != nil {
							return
						}

						isSuspicious := false
						reason := ""

						if len(respBody) > baseLength+500 || len(respBody) < baseLength-500 {
							isSuspicious = true
							reason = "Significant response length change"
						}

						errorKeywords := []string{"sql syntax", "mysql", "postgres", "root:x", "unauthorized", "forbidden", "panic", "error"}
						lowerBody := strings.ToLower(string(respBody))
						for _, keyword := range errorKeywords {
							if strings.Contains(lowerBody, keyword) {
								isSuspicious = true
								reason = fmt.Sprintf("Contains error keyword: '%s'", keyword)
								break
							}
						}

						if isSuspicious {
							mu.Lock()
							results = append(results, FuzzResult{
								URL:          mURL,
								ParamName:    pName,
								Payload:      pld,
								IsSuspicious: true,
								Reason:       reason,
							})
							mu.Unlock()
						}
					}(mutatedURL, param.Name, payload)
				}
			}
		}
	}

	wg.Wait()
	return results
}

func MutateURL(baseURL string, param Parameter, payload string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	if param.Location == "query" {
		q := parsed.Query()
		q.Set(param.Name, payload)
		parsed.RawQuery = q.Encode()
	} else if param.Location == "path" {
		segments := strings.Split(parsed.Path, "/")
		if param.Index >= 0 && param.Index < len(segments) {
			segments[param.Index] = payload
			parsed.Path = strings.Join(segments, "/")
		}
	}

	return parsed.String(), nil
}