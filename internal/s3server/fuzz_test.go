package s3server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzRequestTargetGrammar(f *testing.F) {
	f.Add(http.MethodGet, "/bucket/objects/"+strings.Repeat("0", 128)+"/00000000000000000000000000000000", "")
	f.Add(http.MethodGet, "/bucket", "list-type=2")
	f.Add(http.MethodPut, "/bucket/../escape", "x-id=PutObject")
	f.Fuzz(func(t *testing.T, method, path, query string) {
		if len(method)+len(path)+len(query) > 1<<16 {
			t.Skip()
		}
		request := &http.Request{Method: method, URL: &url.URL{Path: path, RawQuery: query}}
		bucket, key, list, err := parseRequestTarget(request)
		if err != nil {
			return
		}
		if err := validateBucket(bucket); err != nil {
			t.Fatalf("request target accepted invalid bucket %q: %v", bucket, err)
		}
		if list {
			if key != "" || method != http.MethodGet {
				t.Fatalf("invalid accepted list target: method=%q key=%q", method, key)
			}
			return
		}
		if _, err := rawKeyComponents(key); err != nil {
			t.Fatalf("request target accepted invalid key %q: %v", key, err)
		}
	})
}

func FuzzCanonicalQuery(f *testing.F) {
	for _, seed := range []string{"", "list-type=2", "prefix=a%2Fb&max-keys=1000", "%", "a=1&a=0", "plus=not+a+space"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		canonical, err := canonicalQuery(raw)
		if err != nil {
			return
		}
		again, err := canonicalQuery(canonical)
		if err != nil || again != canonical {
			t.Fatalf("canonical query is not idempotent: first=%q second=%q err=%v", canonical, again, err)
		}
	})
}
