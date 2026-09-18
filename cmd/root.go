package cmd

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bughunter [module]",
	Short: "A modular toolkit for Bug Bounty hunters and pentesters.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	// چاپ بنر رنگی و حرفه‌ای
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)

	cyan.Println("\n╔════════════════════════════════════════════════════╗")
	cyan.Println("║ 🛡️       BugHunter Toolkit v1.0.0 (Alpha)       🛡️ ║")
	cyan.Println("║    Advanced Modular Recon & Pentesting Utility     ║")
	cyan.Println("╚════════════════════════════════════════════════════╝")
	yellow.Println("\n           [ Created by @mmahyar639 | Go 1.27+ ]\n")

	// اجرای دستور
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// init is called automatically before main()
func init() {
	// تعریف پرچم‌های عمومی (Global Flags) که در تمام ماژول‌ها کار می‌کنن
	rootCmd.PersistentFlags().StringP("output", "o", "", "Save results to a JSON file")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose logging")
}