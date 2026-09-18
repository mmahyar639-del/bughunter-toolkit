package api_fuzzer

import (
	"net/url"
	"regexp"
	"strings"
)

// ParamType نوع پارامتر را مشخص می‌کند
type ParamType string

const (
	TypeNumeric ParamType = "numeric"
	TypeString  ParamType = "string"
	TypeUUID    ParamType = "uuid"
	TypeUnknown ParamType = "unknown"
)

// Parameter ساختاری برای نگهداری اطلاعات یک پارامتر پیدا شده در URL
type Parameter struct {
	Name     string    // نام پارامتر (مثلاً "id" یا "user_id")
	Value    string    // مقدار فعلی (مثلاً "123")
	Type     ParamType // نوع حدس زده شده
	Location string    // محل پارامتر: "query" یا "path"
	Index    int // اندیس جدید برای پارامترهای مسیر
}

// AnalyzeURL آدرس را تحلیل کرده و پارامترهای آن را استخراج و دسته‌بندی می‌کند
func AnalyzeURL(targetURL string) []Parameter {
	var params []Parameter
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return params
	}

	// ۱. بررسی پارامترهای Query (مثلاً ?id=123&name=test)
	for key, values := range parsedURL.Query() {
		if len(values) > 0 {
			params = append(params, Parameter{
				Name:     key,
				Value:    values[0],
				Type:     detectType(values[0]),
				Location: "query",
			})
		}
	}

	// ۲. بررسی پارامترهای Path (مثلاً /api/users/123)
	// این یک منطق ساده است: بخش‌هایی از مسیر که کاملاً عددی یا UUID هستند
	pathSegments := strings.Split(parsedURL.Path, "/")
	for i, segment := range pathSegments {
		if segment == "" {
			continue
		}
		pType := detectType(segment)
		if pType != TypeUnknown {
			params = append(params, Parameter{
				Name:     "path_param_" + string(rune(i)), // نام موقت برای پارامتر مسیر
				Value:    segment,
				Type:     pType,
				Location: "path",
				Index:    i,
			})
		}
	}

	return params
}

// detectType نوع داده را بر اساس الگوهای Regex حدس می‌زند
func detectType(value string) ParamType {
	// بررسی UUID
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if uuidRegex.MatchString(value) {
		return TypeUUID
	}

	// بررسی عددی
	numericRegex := regexp.MustCompile(`^\d+$`)
	if numericRegex.MatchString(value) {
		return TypeNumeric
	}

	// در غیر این صورت، رشته‌ای در نظر گرفته می‌شود
	return TypeString
}