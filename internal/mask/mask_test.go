package mask

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	e, err := New(Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, in, want string }{
		{"email", "連絡先: alice@example.com", "連絡先: [REDACTED_EMAIL]"},
		{"ip", "192.168.0.1 ::1 2001:db8::1 999.1.1.1", "[REDACTED_IP] [REDACTED_IP] [REDACTED_IP] 999.1.1.1"},
		{"json", `{"password": "secret value", "n": 42}`, `{"password": "[REDACTED_SECRET]", "n": 42}`},
		{"env", "API_KEY=demo-secret\r\nPORT=8080\r\n", "API_KEY=[REDACTED_SECRET]\r\nPORT=[REDACTED_VARIABLE]\r\n"},
		{"bearer", "Authorization: Bearer abcdef123456", "Authorization: [REDACTED_SECRET]"},
		{"basic", "Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l", "Authorization: [REDACTED_SECRET]"},
		{"escaped JSON", `{"password":"a\"hidden suffix"}`, `{"password":"[REDACTED_SECRET]"}`},
		{"empty yaml", "password:\nport: 8080", "password:\nport: 8080"},
		{"card", "4111 1111 1111 1111 / 4111 1111 1111 1112", "[REDACTED_CARD] / 4111 1111 1111 1112"},
		{"key", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"},
		{"url", "postgres://admin:hello@db.local/x", "postgres://[REDACTED_URL_CREDENTIAL]/x"},
		{"token", "ghp_abcdefghijklmnopqrstuvwxyz1234567890", "[REDACTED_TOKEN]"},
		{"plain", "普通の文章\n", "普通の文章\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Mask(tc.in)
			if got.Text != tc.want {
				t.Fatalf("got %q; want %q", got.Text, tc.want)
			}
		})
	}
}

func TestCustomOverlap(t *testing.T) {
	e, err := New(Config{[]Rule{{Name: "PERSON", Literal: "山田太郎"}, {Name: "CUSTOM", Pattern: `abc@example\.com SUFFIX`}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	r := e.Mask("山田太郎 abc@example.com SUFFIX")
	if strings.Contains(r.Text, "SUFFIX") || strings.Contains(r.Text, "山田") {
		t.Fatal(r.Text)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, r := range []Rule{{Name: "bad", Literal: "x"}, {Name: "OK", Pattern: "("}, {Name: "OK", Pattern: ".*"}, {Name: "OK"}} {
		if _, err := New(Config{[]Rule{r}}, false); err == nil {
			t.Fatal("expected invalid rule")
		}
	}
	for _, s := range []string{`{"typo":true}`, `{} {}`, `{"rules":`} {
		if _, err := ReadConfig(strings.NewReader(s)); err == nil {
			t.Fatal("expected config error")
		}
	}
}

func TestPhoneOptIn(t *testing.T) {
	e, _ := New(Config{}, false)
	if e.Mask("090-1234-5678").Text != "090-1234-5678" {
		t.Fatal("phone should be opt in")
	}
	e, _ = New(Config{}, true)
	if e.Mask("090-1234-5678").Text != "[REDACTED_PHONE]" {
		t.Fatal("phone not masked")
	}
}

func FuzzMask(f *testing.F) {
	e, _ := New(Config{}, false)
	f.Add("password=demo alice@example.com")
	f.Add("NAME=\"$(cat 'private file')\"\nadmin@host:~/project# echo ok")
	f.Fuzz(func(t *testing.T, s string) {
		r := e.Mask(s)
		if len(r.Counts) == 0 && r.Text != s {
			t.Fatal("unmatched text changed")
		}
	})
}
