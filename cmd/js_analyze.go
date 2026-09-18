package cmd

import (
	"bytes"
	//"fmt"
	"net/url"
	"sync"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/core"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/js_analyzer"
	"github.com/spf13/cobra"
)

var targetURL string

var jsAnalyzeCmd = &cobra.Command{
	Use:   "js-analyze",
	Short: "Extract secrets and endpoints from JavaScript files",
	Long:  `Downloads JS files concurrently and scans them for high-value secrets using advanced Regex.`,
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n🚀 Starting Advanced JS Analysis module...")
		color.White("🎯 Target: %s", targetURL)

		httpClient := core.NewHTTPClient()

		// ۱. دریافت صفحه اصلی
		body, err := httpClient.Get(targetURL)
		if err != nil {
			color.Red("\n❌ Error fetching page: %v", err)
			return
		}

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
		if err != nil {
			color.Red("\n❌ Error parsing HTML: %v", err)
			return
		}

		var jsFiles []string
		baseURL, _ := url.Parse(targetURL)

		doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
			src, _ := s.Attr("src")
			absURL, err := baseURL.Parse(src)
			if err == nil {
				jsFiles = append(jsFiles, absURL.String())
			}
		})

		if len(jsFiles) == 0 {
			color.Yellow("\n⚠️ No external JavaScript files found.")
			return
		}

		color.Green("\n🎉 Found %d JS file(s). Starting CONCURRENT download & scan...", len(jsFiles))

		// ۲. دانلود و اسکن همزمان (Concurrency)
		var wg sync.WaitGroup
		totalSecrets := 0
		var mu sync.Mutex // برای جلوگیری از تداخل در چاپ همزمان

		for _, jsURL := range jsFiles {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()

				jsBody, err := httpClient.Get(url)
				if err != nil {
					mu.Lock()
					color.Red("   ❌ Failed: %s", url)
					mu.Unlock()
					return
				}

				findings := js_analyzer.ScanContent(string(jsBody))
				
				mu.Lock()
				if len(findings) > 0 {
					color.Red("\n   🚨 FOUND %d FINDING(S) in: %s", len(findings), url)
					for _, f := range findings {
						if strings.Contains(f.Type, "SECRET") {
							color.Yellow("      ├─ %s", f.Type)
							color.Magenta("      └─ 💎 Value: %s", f.Value)
						} else {
							color.Cyan("      ├─ %s", f.Type)
							color.White("      └─ 🔗 Value: %s", f.Value)
						}
					}
					totalSecrets += len(findings)
				} else {
					color.Green("   ✅ Clean: %s", url)
				}
				mu.Unlock()
			}(jsURL)
		}

		// منتظر بمان تا همه گوروتین‌ها تمام شوند
		wg.Wait()

		// ۳. گزارش نهایی
		color.Cyan("\n📊 Final Report:")
		if totalSecrets == 0 {
			color.Green("   🛡️ No secrets found. Target seems clean.")
		} else {
			color.Red("   ⚠️ Total Potential Secrets Found: %d", totalSecrets)
			color.Yellow("   💡 Action: Manually verify these findings before reporting!")
		}
	},
}

func init() {
	rootCmd.AddCommand(jsAnalyzeCmd)
	jsAnalyzeCmd.Flags().StringVarP(&targetURL, "url", "u", "", "Target URL or local file path (e.g., http://test.com or file://test.html)")
	jsAnalyzeCmd.MarkFlagRequired("url")
}