package main

import "testing"

func TestHumanBytes(t *testing.T) {
	for _, test := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048524, "1023.9 KiB"},
		{1<<20 - 1, "1.0 MiB"},
		{5 << 20, "5.0 MiB"},
		{3<<30 + 1<<29, "3.5 GiB"},
		{2 << 40, "2.0 TiB"},
		{^uint64(0), "16.0 EiB"},
	} {
		if got := humanBytes(test.bytes); got != test.want {
			t.Errorf("humanBytes(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
}
