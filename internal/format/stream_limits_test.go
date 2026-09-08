package format

import (
	"math"
	"strings"
	"testing"
)

func TestCanonicalParserSupportsRepresentableFileLimit(t *testing.T) {
	limits := Limits{
		MaxFileBytes:  math.MaxInt64,
		MaxLineBytes:  16 << 10,
		MaxFieldBytes: 8 << 10,
		MaxRecords:    math.MaxInt,
	}
	if err := WalkObjects(strings.NewReader(""), limits, nil); err != nil {
		t.Fatalf("empty catalog with representable file limit: %v", err)
	}
}
