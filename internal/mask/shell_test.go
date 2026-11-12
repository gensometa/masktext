package mask

import (
	"strings"
	"testing"
)

func TestShellValues(t *testing.T) {
	e, _ := New(Config{}, false)
	for _, tc := range []struct{ in, want string }{
		{`NAME="private value"`, `NAME="[REDACTED_VARIABLE]"`},
		{`#WebhookURL2="https://example.invalid/private"`, `#WebhookURL2="[REDACTED_VARIABLE]"`},
		{"RESULT=`cat /root/Private/input.txt`", "RESULT=`[REDACTED_VARIABLE]`"},
		{`RESULT=$(cat "/home/alice/private file")`, `RESULT=[REDACTED_VARIABLE]`},
		{`RESULT="$(printf '%s' "private value")"`, `RESULT="[REDACTED_VARIABLE]"`},
		{`export NAME=private OTHER='another value'`, `export NAME=[REDACTED_VARIABLE] OTHER='[REDACTED_VARIABLE]'`},
		{`NAME=hello\ world; echo done`, `NAME=[REDACTED_VARIABLE]; echo done`},
		{`NAME="first"'second'`, `NAME=[REDACTED_VARIABLE]`},
		{`NAME=${OTHER:-private value}`, `NAME=[REDACTED_VARIABLE]`},
		{`NAME=(one "two three")`, `NAME=[REDACTED_VARIABLE]`},
		{"NAME='first\nsecond'", "NAME='[REDACTED_VARIABLE]'"},
		{"NAME=\nnext command", "NAME=\nnext command"},
		{`curl https://example.invalid/?group=1`, `curl https://example.invalid/?group=1`},
		{`echo ordinary text`, `echo ordinary text`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := e.Mask(tc.in).Text; got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestSyntheticShellTranscript(t *testing.T) {
	e, _ := New(Config{}, false)
	input := "admin@PrivateServer:~/SecretProject# cat update.sh\n" +
		"#WebhookURL=\"https://discord.com/api/webhooks/123456789/FAKE_TOKEN_NOT_A_REAL_SECRET\"\n" +
		"WebhookURL2=\"https://discord.com/api/webhooks/987654321/OTHER_FAKE_TOKEN?thread_id=12345\"\n" +
		"curl -s https://example.invalid/news/?group=1 >/root/SecretProject/output\n" +
		"/usr/bin/python3 /root/SecretProject/news.py\n" +
		"NEWS=`cat /root/SecretProject/input.txt`\n"
	got := e.Mask(input).Text
	for _, value := range []string{"admin", "PrivateServer", "SecretProject", "discord.com", "FAKE_TOKEN", "thread_id", "12345", "input.txt"} {
		if strings.Contains(got, value) {
			t.Fatalf("sensitive synthetic value remains: %s", value)
		}
	}
	for _, value := range []string{"[REDACTED_USER]@[REDACTED_HOST]:[REDACTED_PATH]# cat update.sh", "#WebhookURL=", "WebhookURL2=", "NEWS=", "https://example.invalid/news/?group=1", "/usr/bin/python3"} {
		if !strings.Contains(got, value) {
			t.Fatalf("lost expected structure %q: %s", value, got)
		}
	}
}

func TestStandaloneWebhook(t *testing.T) {
	e, _ := New(Config{}, false)
	for _, host := range []string{"discord.com", "canary.discord.com", "ptb.discord.com", "discordapp.com"} {
		got := e.Mask("URL: https://" + host + "/api/v10/webhooks/123/FAKE_TOKEN?thread_id=456").Text
		if got != "URL: [REDACTED_WEBHOOK]" {
			t.Fatal(got)
		}
	}
}

func TestDeepShellSubstitution(t *testing.T) {
	e, _ := New(Config{}, false)
	input := "VALUE=" + strings.Repeat("$(", 1024) + "private-value" + strings.Repeat(")", 1024)
	if strings.Contains(e.Mask(input).Text, "private-value") {
		t.Fatal("nested value was not redacted")
	}
}
