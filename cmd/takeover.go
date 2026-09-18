package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/mmahyar639-del/bughunter-toolkit/internal/modules/takeover"
	"github.com/spf13/cobra"
)

var subdomainList string

var takeoverCmd = &cobra.Command{
	Use:   "takeover",
	Short: "Check subdomains for potential takeover vulnerabilities",
	Long:  `Reads a list of subdomains from a file, resolves their DNS, and checks for dangling CNAMEs matching known vulnerable services (GitHub Pages, Heroku, AWS S3, etc.).`,
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("\n🚀 Starting Subdomain Takeover Scanner...")
		color.White("📂 Target List: %s", subdomainList)

		// ۱. خواندن لیست ساب‌دامین‌ها
		color.Yellow("\n⏳ Reading subdomains from file...")
		subs, err := takeover.ReadSubdomainsFromFile(subdomainList)
		if err != nil {
			color.Red("\n❌ Error reading file: %v", err)
			return
		}
		color.Green("✅ Loaded %d subdomains.", len(subs))

		// ۲. بررسی DNS
		color.Yellow("\n⏳ Resolving DNS and checking CNAMEs...")
		dnsResults := takeover.CheckSubdomains(subs)

		// ۳. تأیید نهایی با HTTP
		color.Yellow("⏳ Verifying potential takeovers via HTTP...")
		confirmedResults := takeover.ConfirmTakeover(dnsResults)

		// ۴. گزارش نهایی
		fmt.Println("\n" + strings.Repeat("=", 60))
		color.Cyan("📊 FINAL REPORT:")
		fmt.Println(strings.Repeat("=", 60))

		if len(confirmedResults) == 0 {
			color.Green("✅ No confirmed subdomain takeovers found. Target seems secure.")
		} else {
			color.Red("🚨 CRITICAL: Found %d CONFIRMED Subdomain Takeover(s)!", len(confirmedResults))
			for _, res := range confirmedResults {
				color.Yellow("\n🎯 Subdomain: %s", res.Subdomain)
				color.White("   ├─ Service : %s", res.Service)
				color.White("   ├─ CNAME   : %v", res.CNAMEs)
				color.Magenta("   └─ Status  : CONFIRMED VULNERABLE")
			}
			color.Yellow("\n💡 Action: Verify manually and report to the vendor!")
		}
		fmt.Println(strings.Repeat("=", 60))
	},
}

func init() {
	rootCmd.AddCommand(takeoverCmd)
	takeoverCmd.Flags().StringVarP(&subdomainList, "list", "l", "", "Path to the text file containing subdomains (e.g., subs.txt)")
	takeoverCmd.MarkFlagRequired("list")
}