package js_analyzer

import (
	"regexp"
	"strings"
)

type Finding struct {
	Type  string
	Value string
}

var SecretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key ID":       regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	"AWS Secret Access Key":   regexp.MustCompile(`(?i)aws.{0,20}?['\"][0-9a-zA-Z\/+]{40}['\"]`),
	"GitHub Personal Token":   regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
	"Google API Key":          regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
	"Stripe Secret Key":       regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),
	"Slack Webhook URL":       regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
	"Generic API Key/Secret":  regexp.MustCompile(`(?i)(api_key|apikey|secret|password|auth_token)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?`),
	"Private Key Header":      regexp.MustCompile(`(?i)-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----`),
	"JWT Token":               regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"Database Connection":     regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis):\/\/[^\s'"]+`),
}

// الگوهای جدید برای استخراج Endpointها و URLهای داخلی
var EndpointPatterns = map[string]*regexp.Regexp{
	"API Route":         regexp.MustCompile(`(?i)(?:\/|\.)(api|v[0-9]+|internal|admin|graphql|webhook)[a-zA-Z0-9_\-\/\.]*`),
	"Hidden Parameter":  regexp.MustCompile(`(?i)[\?&](id|user|key|token|secret|file|path|redirect|url|debug|test)=[a-zA-Z0-9\-_]+`),
	"Internal Domain":   regexp.MustCompile(`(?i)(?:https?:\/\/)?(?:[\w\-]+\.)+(?:local|internal|dev|staging|corp|test)[\w\-\.]*`),
}

func ScanContent(content string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// ۱. اسکن Secrets
	for secretType, pattern := range SecretPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			clean := strings.TrimSpace(match)
			if len(clean) > 15 && !seen[clean] {
				seen[clean] = true
				findings = append(findings, Finding{Type: "🔑 SECRET: " + secretType, Value: clean})
			}
		}
	}

	// ۲. اسکن Endpoints
	for endpointType, pattern := range EndpointPatterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			clean := strings.TrimSpace(match)
			// فیلتر کردن نتایج خیلی کوتاه یا تکراری
			if len(clean) > 8 && !seen[clean] {
				seen[clean] = true
				findings = append(findings, Finding{Type: "🔗 ENDPOINT: " + endpointType, Value: clean})
			}
		}
	}

	return findings
}