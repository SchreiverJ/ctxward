package vault

import (
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestAutomatonMatchesNaiveSearch(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alpha := "abc" // tiny alphabet forces overlaps and suffix links
	rnd := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[rng.Intn(len(alpha))]
		}
		return string(b)
	}
	for round := 0; round < 300; round++ {
		var terms []string
		seen := map[string]bool{}
		for i := 0; i < 1+rng.Intn(8); i++ {
			if s := rnd(1 + rng.Intn(5)); !seen[s] {
				seen[s] = true
				terms = append(terms, s)
			}
		}
		text := rnd(rng.Intn(60))
		want := map[[3]int]bool{}
		for ti, s := range terms {
			for i := 0; i+len(s) <= len(text); i++ {
				if text[i:i+len(s)] == s {
					want[[3]int{i, i + len(s), ti}] = true
				}
			}
		}
		got := map[[3]int]bool{}
		newAutomaton(terms).scan(text, func(s, e, ti int) bool { got[[3]int{s, e, ti}] = true; return true })
		if len(got) != len(want) {
			t.Fatalf("terms %q text %q: got %v want %v", terms, text, got, want)
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("terms %q text %q: missing %v", terms, text, k)
			}
		}
	}
}

func TestModesAndNames(t *testing.T) {
	v, st := New([]Spec{{"STRIPE_KEY", Both}, {"GH_TOKEN", ValueOnly}},
		env(map[string]string{"STRIPE_KEY": "sk_live_abcdef123456", "GH_TOKEN": "ghp_zyxwvu987654"}))
	if st.ValuesSkipped != 0 {
		t.Fatal(st)
	}
	in := `os.environ["STRIPE_KEY"] = sk_live_abcdef123456; GH_TOKEN=ghp_zyxwvu987654 MY_STRIPE_KEY2 STRIPE_KEYS`
	got, changed := v.Redact(in)
	want := `os.environ["[REDACTED]"] = [REDACTED]; GH_TOKEN=[REDACTED] MY_STRIPE_KEY2 STRIPE_KEYS`
	if !changed || got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	if v.Contains("GH_TOKEN") || !v.Contains("STRIPE_KEY") {
		t.Fatal("per-variable name protection wrong")
	}
	if again, changed := v.Redact(got); changed || again != got {
		t.Fatal("redacted text must scan clean")
	}
}

func TestEncodings(t *testing.T) {
	const secret = `p@ss w0rd/"x"&y=z`
	v, _ := New([]Spec{{"DB", ValueOnly}}, env(map[string]string{"DB": secret}))
	for _, c := range []string{secret, "q=p%40ss+w0rd%2F%22x%22%26y%3Dz", "/p@ss%20w0rd%2F%22x%22&y=z", "/p%40ss%20w0rd%2F%22x%22%26y%3Dz"} {
		if !v.Contains("x " + c + " y") {
			t.Errorf("missed %q", c)
		}
	}
	// JSON text (cat config.json, kubectl -o json), HTML-escaped or not, and lowercase percent-hex.
	jsonSecret := `a"b\c/<d>&efgh`
	jv, _ := New([]Spec{{"J", ValueOnly}}, env(map[string]string{"J": jsonSecret}))
	for _, c := range []string{`{"k":"a\"b\\c/<d>&efgh"}`, `a\"b\\c\/<d>&efgh`, `a\"b\\c/\u003cd\u003e\u0026efgh`, "a%22b%5cc%2f%3cd%3e%26efgh"} {
		if !jv.Contains(c) {
			t.Errorf("missed JSON/percent form %q", c)
		}
	}
	// base64 anywhere inside a longer base64 string, at every alignment.
	for pre := 0; pre < 6; pre++ {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			for suf := 0; suf < 4; suf++ {
				payload := strings.Repeat("u", pre) + secret + strings.Repeat("v", suf)
				if text := "Basic " + enc.EncodeToString([]byte(payload)); !v.Contains(text) {
					t.Errorf("missed base64 pre=%d suf=%d: %s", pre, suf, text)
				}
			}
		}
	}
}

func TestSkipsAndSettling(t *testing.T) {
	v, st := New([]Spec{{"SHORT", Both}, {"UNSET", ValueOnly}, {"REDACTED", Both}, {"OK", ValueOnly}},
		env(map[string]string{"SHORT": "true", "OK": "REDACTED"}))
	if st.ValuesSkipped != 3 || st.Variables != 4 {
		t.Fatal(st)
	}
	// A short value is not searched for, but the name still is.
	if got, _ := v.Redact("true SHORT"); got != "true [REDACTED]" {
		t.Fatal(got)
	}
	// Terms inside our own placeholder are dropped, so output is stable.
	out, _ := v.Redact("SHORT REDACTED")
	if again, changed := v.Redact(out); changed {
		t.Fatalf("not settled: %q -> %q", out, again)
	}
}

func TestMultilineValueAndOverlap(t *testing.T) {
	pem := "-----BEGIN KEY-----\nAAAABBBBCCCC\nDDDDEEEEFFFF\n-----END KEY-----"
	v, _ := New([]Spec{{"PEM", ValueOnly}}, env(map[string]string{"PEM": pem}))
	if got, _ := v.Redact("x AAAABBBBCCCC y"); got != "x [REDACTED] y" {
		t.Fatal(got)
	}
	if got, _ := v.Redact(pem); got != "[REDACTED]" {
		t.Fatalf("overlapping matches must merge: %q", got)
	}
}

func TestEmptyAndConfig(t *testing.T) {
	var zero Vault
	if zero.Contains("anything") {
		t.Fatal()
	}
	specs, err := ParseConfig(strings.NewReader("# c\nA_B\nC value # x\n\nD both\n"))
	if err != nil || len(specs) != 3 || specs[0].Mode != ValueOnly || specs[1].Mode != ValueOnly || specs[2].Mode != Both {
		t.Fatal(specs, err)
	}
	for _, bad := range []string{"1BAD", "A B C", "A sometimes"} {
		if _, err := ParseConfig(strings.NewReader(bad)); err == nil || strings.Contains(err.Error(), "BAD") {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestFilterStreamsLinesAndFailsOnHugeLine(t *testing.T) {
	v, _ := New([]Spec{{"K", Both}}, env(map[string]string{"K": "supersecretvalue"}))
	var out strings.Builder
	in := "a supersecretvalue b\nK=1\nno newline supersecretvalue"
	if err := v.Filter(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if want := "a [REDACTED] b\n[REDACTED]=1\nno newline [REDACTED]"; out.String() != want {
		t.Fatalf("got %q", out.String())
	}
	out.Reset()
	huge := strings.Repeat("x", MaxLine+10)
	if err := v.Filter(strings.NewReader("ok\n"+huge), &out); err != ErrLineTooLong || out.String() != "ok\n" {
		t.Fatalf("err=%v out=%d bytes", err, out.Len())
	}
}
