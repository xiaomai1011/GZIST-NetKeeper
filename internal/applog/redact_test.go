package applog

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	r := Redactor{Accounts: []string{"2023100001"}, KeepIPs: []string{"10.0.10.252", "10.128.255.143"}}
	for _, c := range [][2]string{
		{"账号 2023100001 已保存", "账号 2023***001 已保存"},
		{"DDDDD=%2C0%2C2023100001&upass=***", "DDDDD=%2C0%2C2023***001&upass=***"},
		{"网卡 en0  IP 10.20.30.40  MAC AABBCCDDEEFF", "网卡 en0  IP 10.20.*.*  MAC AABBCC******"},
		{"[网卡] ✓ en0  MAC AA-BB-CC-DD-EE-FF", "[网卡] ✓ en0  MAC AA-BB-CC-**-**-**"},
		{"mac=aa:bb:cc:dd:ee:ff", "mac=aa:bb:cc:**:**:**"},
		{"wlanacip=10.128.255.143&wlanacip=10.128.255.200", "wlanacip=10.128.255.143&wlanacip=10.128.*.*"},
		{"http://10.0.10.252:801/eportal/", "http://10.0.10.252:801/eportal/"},
		{"other id 202211223344 here", "other id 2022***344 here"},
		{"2026-10-08 15:04:05  ret_code=8", "2026-10-08 15:04:05  ret_code=8"},
	} {
		if got := r.Line(c[0]); got != c[1] {
			t.Errorf("Line(%q)\n got %q\nwant %q", c[0], got, c[1])
		}
	}
}

func TestRedactAllDigitMAC(t *testing.T) {
	got := Redactor{}.Line("MAC 001122334455")
	if strings.Contains(got, "334455") {
		t.Fatalf("not masked: %s", got)
	}
}
