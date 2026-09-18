package cmd

import (
	"github.com/fatih/color"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/api_fuzzer"
	"github.com/spf13/cobra"
)

var fuzzURL string

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Smart API Fuzzer for IDOR, SQLi, XSS, and LFI",
	Long:  `Analyzes the target URL, identifies parameter types, and injects smart payloads to detect vulnerabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n🚀 Starting Smart API Fuzzer...")
		color.White("🎯 Target: %s", fuzzURL)

		color.Yellow("\n⏳ Analyzing URL structure and generating smart payloads...")
		
		// تغییر اصلی اینجاست: استفاده از RunFuzzerBatch و قرار دادن URL در یک اسلایس
		results := api_fuzzer.RunFuzzerBatch([]string{fuzzURL})

		if len(results) == 0 {
			color.Green("\n✅ Scan completed. No suspicious behavior detected.")
			return
		}

		color.Red("\n🚨 FOUND %d SUSPICIOUS RESPONSE(S)!", len(results))
		for _, res := range results {
			color.Yellow("\n   📍 Parameter: %s", res.ParamName)
			color.Magenta("   🔫 Payload: %s", res.Payload)
			color.White("   🔗 URL: %s", res.URL)
			color.Red("   ⚠️ Reason: %s", res.Reason)
		}
		
		color.Cyan("\n💡 Action: Manually verify these URLs in Burp Suite or browser.")
	},
}

func init() {
	rootCmd.AddCommand(fuzzCmd)
	fuzzCmd.Flags().StringVarP(&fuzzURL, "url", "u", "", "Target URL to fuzz (e.g., https://api.target.com/v1/users?id=123)")
	fuzzCmd.MarkFlagRequired("url")
}