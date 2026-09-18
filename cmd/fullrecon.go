package cmd

import (
	"fmt"
	"strings"
	"time"
	"net/url"

	"github.com/fatih/color"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/core"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/api_fuzzer"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/js_analyzer"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/takeover"
	"github.com/spf13/cobra"
)

var (
	fullReconDomain string
	fullReconSubs   string
	fullReconOutput string
)

var fullReconCmd = &cobra.Command{
	Use:   "full-recon",
	Short: "Run complete automated pipeline and generate HTML report",
	Long:  `Executes JS Analyzer, pipes endpoints to Smart API Fuzzer, checks Subdomain Takeover, and generates a beautiful HTML report.`,
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n🚀 Starting Full Automated Recon Pipeline...")
		color.White("🎯 Target Domain: %s", fullReconDomain)
		startTime := time.Now()

		reportData := HTMLReportData{
			Target:    fullReconDomain,
			Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		}

		httpClient := core.NewHTTPClient()
		targetURL := "https://" + fullReconDomain

		// ═══════════════════════════════════════════════════════════════
		// PHASE 1: JS Analyzer
		// ═══════════════════════════════════════════════════════════════
		color.Yellow("\n" + strings.Repeat("=", 60))
		color.Cyan("📍 PHASE 1: JS Analyzer")
		color.Yellow(strings.Repeat("=", 60))

		body, err := httpClient.Get(targetURL)
		if err != nil {
			color.Red("❌ Failed to fetch target: %v", err)
		} else {
			color.Green("✅ Fetched main page (%d bytes)", len(body))
			// اسکن محتوای صفحه اصلی و فایل‌های JS (برای سادگی فعلاً خود صفحه اصلی اسکن می‌شود)
			// در نسخه‌های بعدی می‌توان لینک‌های JS را استخراج و دانلود کرد
			findings := js_analyzer.ScanContent(string(body))
			reportData.JSSecrets = findings

			if len(findings) > 0 {
				color.Red("🚨 Found %d secrets/endpoints", len(findings))
			} else {
				color.Green("✅ No secrets found in main page")
			}
		}

		// ═══════════════════════════════════════════════════════════════
		// PHASE 2: Smart API Fuzzer (Chained from Phase 1 with Smart Filtering)
		// ═══════════════════════════════════════════════════════════════
		color.Yellow("\n" + strings.Repeat("=", 60))
		color.Cyan("📍 PHASE 2: Smart API Fuzzer (Chained)")
		color.Yellow(strings.Repeat("=", 60))

		// استخراج و فیلتر کردن هوشمند اندپوینت‌ها از فاز ۱
		var endpointsToFuzz []string
		for _, finding := range reportData.JSSecrets {
			if strings.Contains(finding.Type, "ENDPOINT") {
				targetEndpoint := finding.Value
				
				// ۱. تبدیل به URL مطلق
				if !strings.HasPrefix(targetEndpoint, "http") {
					targetEndpoint = targetURL + strings.TrimPrefix(targetEndpoint, "/")
				}

				// ۲. فیلتر کردن فایل‌های استاتیک (جلوگیری از اتلاف وقت)
				lowerURL := strings.ToLower(targetEndpoint)
				if strings.HasSuffix(lowerURL, ".png") || strings.HasSuffix(lowerURL, ".jpg") || 
				   strings.HasSuffix(lowerURL, ".svg") || strings.HasSuffix(lowerURL, ".mp4") || 
				   strings.HasSuffix(lowerURL, ".css") || strings.HasSuffix(lowerURL, ".js") {
					continue
				}

				// ۳. فیلتر کردن پارامترهای بی‌معنی روی روت دامنه (مثل ?id=GTM)
				parsedURL, err := url.Parse(targetEndpoint)
				if err == nil {
					// اگر مسیر فقط "/" است، احتمالاً یک پارامتر ردیابی (Tracking) است، نه API
					if parsedURL.Path == "/" || parsedURL.Path == "" {
						continue
					}
					
					// اگر مسیر شامل api یا نسخه‌بندی است، یا پارامتر کوئری واقعی دارد، آن را اضافه کن
					if strings.Contains(strings.ToLower(parsedURL.Path), "/api") || 
					   strings.Contains(strings.ToLower(parsedURL.Path), "/v1") || 
					   strings.Contains(strings.ToLower(parsedURL.Path), "/v2") || 
					   parsedURL.RawQuery != "" {
						endpointsToFuzz = append(endpointsToFuzz, targetEndpoint)
					}
				}
			}
		}

		// اگر اندپوینت معتبری پیدا نشد، یک آدرس پیش‌فرض را تست می‌کنیم
		if len(endpointsToFuzz) == 0 {
			endpointsToFuzz = append(endpointsToFuzz, targetURL+"/api/v1/users?id=1")
			color.Yellow("⚠️ No valid API endpoints found in JS. Testing default API path.")
		} else {
			color.Green("✅ Smartly chained %d valid endpoints to Fuzzer...", len(endpointsToFuzz))
		}

		fuzzResults := api_fuzzer.RunFuzzerBatch(endpointsToFuzz)
		reportData.FuzzResults = fuzzResults

		if len(fuzzResults) > 0 {
			color.Red("🚨 Found %d suspicious responses", len(fuzzResults))
		} else {
			color.Green("✅ No anomalies detected in API")
		}

		// ═══════════════════════════════════════════════════════════════
		// PHASE 3: Subdomain Takeover
		// ═══════════════════════════════════════════════════════════════
		color.Yellow("\n" + strings.Repeat("=", 60))
		color.Cyan("📍 PHASE 3: Subdomain Takeover")
		color.Yellow(strings.Repeat("=", 60))

		var subs []string
		if fullReconSubs != "" {
			subs, err = takeover.ReadSubdomainsFromFile(fullReconSubs)
			if err != nil {
				color.Red("❌ Error reading subdomains file: %v", err)
			} else {
				color.Green("✅ Loaded %d subdomains from file", len(subs))
			}
		} else {
			subs = []string{"www." + fullReconDomain, "api." + fullReconDomain, "blog." + fullReconDomain}
			color.Yellow("⚠️ No subdomain list provided. Using default subdomains.")
		}

		dnsResults := takeover.CheckSubdomains(subs)
		confirmedTakeovers := takeover.ConfirmTakeover(dnsResults)
		reportData.Takeovers = confirmedTakeovers

		if len(confirmedTakeovers) > 0 {
			color.Red("🚨 Found %d confirmed takeovers!", len(confirmedTakeovers))
		} else {
			color.Green("✅ No subdomain takeovers found")
		}

		// ═══════════════════════════════════════════════════════════════
		// PHASE 4: Generate Beautiful HTML Report
		// ═══════════════════════════════════════════════════════════════
		color.Yellow("\n" + strings.Repeat("=", 60))
		color.Cyan("📊 GENERATING HTML REPORT")
		color.Yellow(strings.Repeat("=", 60))

		outputFile := fullReconOutput
		if outputFile == "" {
			outputFile = fmt.Sprintf("BugHunter_Report_%s.html", time.Now().Format("20060102_150405"))
		}

		err = GenerateHTMLReport(reportData, outputFile)
		if err != nil {
			color.Red("❌ Error saving HTML report: %v", err)
			return
		}

		duration := time.Since(startTime)
		color.Green("\n✅ Full Recon completed in %v", duration.Round(time.Second))
		color.Cyan("💾 Beautiful HTML Report saved to: %s", outputFile)
		
		fmt.Println("\n" + strings.Repeat("=", 60))
		color.Cyan("📈 SUMMARY:")
		color.White("   ├─ JS Secrets/Endpoints : %d", len(reportData.JSSecrets))
		color.White("   ├─ Fuzz Anomalies       : %d", len(reportData.FuzzResults))
		color.White("   └─ Takeovers            : %d", len(reportData.Takeovers))
		fmt.Println(strings.Repeat("=", 60))
	},
}

func init() {
	rootCmd.AddCommand(fullReconCmd)
	fullReconCmd.Flags().StringVarP(&fullReconDomain, "domain", "d", "", "Target domain (e.g., example.com)")
	fullReconCmd.Flags().StringVarP(&fullReconSubs, "subdomains", "s", "", "Path to subdomains list file (optional)")
	fullReconCmd.Flags().StringVarP(&fullReconOutput, "output", "o", "", "Output HTML file path (default: auto-generated)")
	fullReconCmd.MarkFlagRequired("domain")
}