package sanitize

import (
	"regexp"
)

const (
	Redacted            = "[redacted]"
	sensitiveKeyPattern = `(?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|x[_-]?api[_-]?key|x[_-]?goog[_-]?api[_-]?key|client[_-]?secret|private[_-]?key|proxy[_-]?authorization|authorization|password|passwd|credential|cookie|session[_-]?id|session|secret|token|auth)`
)

var (
	pemBlockRE            = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9][A-Z0-9 -]{0,63}-----.*?-----END [A-Z0-9][A-Z0-9 -]{0,63}-----`)
	sensitiveAssignmentRE = regexp.MustCompile(
		`(?i)(\b` + sensitiveKeyPattern + `\b["']?\s*[:=]\s*)` +
			`(?:"[^"\r\n]*"|'[^'\r\n]*'|Bearer[ \t]+(?:\[redacted\]|[^\s,;&}\]\r\n"']+)|\[redacted\]|[^\s,;&}\]\r\n]+)`,
	)
	keyAssignmentRE = regexp.MustCompile(
		`(?i)((?:\bkey\s*=|["']key["']\s*[:=])\s*)` +
			`(?:"[^"\r\n]*"|'[^'\r\n]*'|\[redacted\]|[^\s,;&}\]\r\n]+)`,
	)
	bearerRE       = regexp.MustCompile(`(?i)\bBearer[ \t]+(?:\[redacted\]|[^\s,;&}\]\r\n"']+)`)
	emailRE        = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	gatewayTokenRE = regexp.MustCompile(`\bllmgw_[A-Za-z0-9_-]{32}([^A-Za-z0-9_-]|$)`)
	tokenRE        = regexp.MustCompile(`(?i)\b(?:gh[oupsr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|sk-[A-Za-z0-9_-]{10,}|gsk_[A-Za-z0-9_-]{10,})\b`)
	longValueRE    = regexp.MustCompile(`\b[A-Za-z0-9]{20,}\b`)
)

func SanitizeText(text string) string {
	text = SanitizeIdentifier(text)
	return longValueRE.ReplaceAllString(text, Redacted)
}

func SanitizeIdentifier(text string) string {
	text = pemBlockRE.ReplaceAllString(text, Redacted)
	text = sensitiveAssignmentRE.ReplaceAllString(text, "${1}"+Redacted)
	text = keyAssignmentRE.ReplaceAllString(text, "${1}"+Redacted)
	text = bearerRE.ReplaceAllString(text, "Bearer "+Redacted)
	text = emailRE.ReplaceAllString(text, Redacted)
	text = tokenRE.ReplaceAllString(text, Redacted)
	text = gatewayTokenRE.ReplaceAllString(text, Redacted+"$1")
	return text
}

func SanitizeTextLimit(text string, maxChars int) string {
	return limitText(SanitizeText(text), maxChars)
}

func limitText(text string, maxChars int) string {
	if maxChars <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) > maxChars {
		return string(runes[:maxChars])
	}
	return text
}
