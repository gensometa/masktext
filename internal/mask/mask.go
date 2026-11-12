// Package mask performs offline text redaction.
package mask

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
)

type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Literal string `json:"literal"`
}
type Config struct {
	Rules []Rule `json:"rules"`
}
type detector struct {
	name  string
	re    *regexp.Regexp
	group int
	valid func(string) bool
}
type Engine struct{ detectors []detector }
type Result struct {
	Text   string
	Counts map[string]int
}
type span struct {
	start, end int
	name       string
	priority   int
}

func ReadConfig(r io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid rule configuration")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("configuration must contain one JSON object")
	}
	return c, nil
}

func New(c Config, phone bool) (*Engine, error) {
	e := &Engine{}
	add := func(name, pattern string, group int, valid func(string) bool) {
		e.detectors = append(e.detectors, detector{name, regexp.MustCompile(pattern), group, valid})
	}
	add("PRIVATE_KEY", `(?s)-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`, 0, nil)
	add("TOKEN", `\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`, 0, nil)
	add("JWT", `\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`, 0, nil)
	add("SECRET", `(?i)(?:["']?(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)["']?[ \t]*[:=][ \t]*)(?:"((?:\\.|[^"\\\r\n])+)"|'((?:\\.|[^'\\\r\n])+)'|((?:(?:Bearer|Basic)[ \t]+)?[^\s,;\x22\x27}\]]+))`, -1, nil)
	add("BEARER", `(?i)\bBearer[ \t]+([A-Za-z0-9._~+/-]+=*)`, 1, nil)
	add("URL_CREDENTIAL", `(?i)\b[a-z][a-z0-9+.-]*://([^\s/@]+(?::[^\s/@]*)?)@`, 1, nil)
	add("EMAIL", `(?i)[a-z0-9.!#$%&'*+/=?^_`+"`"+`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}`, 0, nil)
	add("IP", `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`, 0, func(s string) bool { return net.ParseIP(s) != nil })
	add("IP", `[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[a-zA-Z0-9]+)?`, 0, func(s string) bool { host, _, _ := strings.Cut(s, "%"); return net.ParseIP(host) != nil })
	add("CARD", `\b[0-9](?:[ -]?[0-9]){12,18}\b`, 0, luhn)
	if phone {
		add("PHONE", `(?:\+?[0-9][0-9 ()-]{7,}[0-9])`, 0, func(s string) bool {
			n := 0
			for _, r := range s {
				if r >= '0' && r <= '9' {
					n++
				}
			}
			return n >= 10 && n <= 15
		})
	}
	for i, r := range c.Rules {
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,39}$`).MatchString(r.Name) {
			return nil, fmt.Errorf("rule %d: name must be an uppercase identifier", i+1)
		}
		if (r.Pattern == "") == (r.Literal == "") {
			return nil, fmt.Errorf("rule %d: provide exactly one pattern or literal", i+1)
		}
		p := r.Pattern
		if r.Literal != "" {
			p = regexp.QuoteMeta(r.Literal)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("rule %d: invalid regular expression", i+1)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("rule %d: pattern must not match empty text", i+1)
		}
		e.detectors = append(e.detectors, detector{r.Name, re, 0, nil})
	}
	return e, nil
}

func luhn(s string) bool {
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	varied := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if d != digits[0] {
			varied = true
		}
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return varied && sum%10 == 0
}

func (e *Engine) Mask(s string) Result {
	var spans []span
	for priority, d := range e.detectors {
		for _, m := range d.re.FindAllStringSubmatchIndex(s, -1) {
			g := d.group
			if g < 0 {
				for j := 1; j < len(m)/2; j++ {
					if m[2*j] >= 0 {
						g = j
						break
					}
				}
			}
			if g < 0 || 2*g+1 >= len(m) {
				continue
			}
			start, end := m[2*g], m[2*g+1]
			if start < 0 || start == end {
				continue
			}
			if d.valid != nil && !d.valid(s[start:end]) {
				continue
			}
			spans = append(spans, span{start, end, d.name, priority})
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		if spans[i].end != spans[j].end {
			return spans[i].end > spans[j].end
		}
		return spans[i].priority < spans[j].priority
	})
	// Merge overlapping detections so that no uncovered suffix of a secret leaks.
	var merged []span
	for _, s := range spans {
		n := len(merged)
		if n > 0 && s.start < merged[n-1].end {
			if s.end > merged[n-1].end {
				merged[n-1].end = s.end
			}
			continue
		}
		merged = append(merged, s)
	}
	var b strings.Builder
	pos := 0
	counts := map[string]int{}
	for _, m := range merged {
		b.WriteString(s[pos:m.start])
		b.WriteString("[REDACTED_" + m.name + "]")
		counts[m.name]++
		pos = m.end
	}
	b.WriteString(s[pos:])
	return Result{b.String(), counts}
}
