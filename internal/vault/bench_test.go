package vault

import (
	"fmt"
	"math/rand"
	"testing"
)

func benchVault(n int) (*Vault, []Spec, func(string) string) {
	rng := rand.New(rand.NewSource(1))
	vals := map[string]string{}
	var specs []Spec
	for i := 0; i < n; i++ {
		b := make([]byte, 40)
		for j := range b {
			b[j] = byte(33 + rng.Intn(90))
		}
		name := fmt.Sprintf("VAR_%d", i)
		vals[name] = string(b)
		specs = append(specs, Spec{name, Both})
	}
	get := func(k string) string { return vals[k] }
	v, _ := New(specs, get)
	return v, specs, get
}

func BenchmarkBuild(b *testing.B) {
	for _, n := range []int{5, 20, 100} {
		_, specs, get := benchVault(n)
		b.Run(fmt.Sprint(n, "vars"), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				New(specs, get)
			}
		})
	}
}

func BenchmarkScan1MB(b *testing.B) {
	text := make([]byte, 1<<20)
	rng := rand.New(rand.NewSource(2))
	for i := range text {
		text[i] = byte(32 + rng.Intn(90))
	}
	s := string(text)
	for _, n := range []int{5, 20, 100} {
		v, _, _ := benchVault(n)
		b.Run(fmt.Sprint(n, "vars"), func(b *testing.B) {
			b.SetBytes(int64(len(s)))
			for i := 0; i < b.N; i++ {
				v.Contains(s)
			}
		})
	}
}
