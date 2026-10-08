package applog

import (
	"regexp"
	"slices"
	"strings"
)

// Redactor masks personal data in log lines so they can be shared:
// student IDs become 2023***001, IPs 10.20.*.* and MACs AA-BB-CC-**-**-**.
// Passwords never reach the log in the first place.
type Redactor struct {
	Accounts []string // student IDs to mask wherever they appear
	KeepIPs  []string // well-known addresses (portal, ACs) left readable
}

var (
	reIPv4 = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b`)
	// MACs with separators: AA-BB-CC-DD-EE-FF, aa:bb:...
	reMACSep = regexp.MustCompile(`(?i)\b([0-9a-f]{2})([-:])([0-9a-f]{2})[-:]([0-9a-f]{2})[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}\b`)
	// MACs without separators. All-digit matches are left to reDigits.
	reMACPlain = regexp.MustCompile(`(?i)\b[0-9a-f]{12}\b`)
	// Long digit runs look like student IDs, also inside ",0,2023..." and
	// URL-encoded forms.
	reDigits = regexp.MustCompile(`\d{8,}`)
)

// MaskID turns 2023100001 into 2023***001.
func MaskID(id string) string {
	r := []rune(id)
	switch {
	case len(r) >= 8:
		return string(r[:4]) + "***" + string(r[len(r)-3:])
	case len(r) >= 3:
		return string(r[:1]) + "***" + string(r[len(r)-1:])
	case len(r) > 0:
		return "***"
	}
	return ""
}

// Line returns s with personal data masked.
func (r Redactor) Line(s string) string {
	for _, a := range r.Accounts {
		if a = strings.TrimSpace(a); a != "" {
			s = strings.ReplaceAll(s, a, MaskID(a))
		}
	}
	s = reMACSep.ReplaceAllStringFunc(s, func(m string) string {
		sub := reMACSep.FindStringSubmatch(m)
		sep := sub[2]
		return strings.Join([]string{sub[1], sub[3], sub[4], "**", "**", "**"}, sep)
	})
	s = reMACPlain.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Trim(m, "0123456789") == "" {
			return m
		}
		return m[:6] + "******"
	})
	s = reDigits.ReplaceAllStringFunc(s, MaskID)
	s = reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		if slices.Contains(r.KeepIPs, m) {
			return m
		}
		sub := reIPv4.FindStringSubmatch(m)
		return sub[1] + "." + sub[2] + ".*.*"
	})
	return s
}

// Lines masks every line.
func (r Redactor) Lines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = r.Line(l)
	}
	return out
}
