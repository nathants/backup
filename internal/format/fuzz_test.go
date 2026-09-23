package format

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzCanonicalMetadataParsers(f *testing.F) {
	validFormat, err := NewRepositoryFormat(
		"123e4567-e89b-42d3-a456-426614174000",
	).MarshalText()
	if err != nil {
		f.Fatal(err)
	}
	seeds := []struct {
		kind byte
		data []byte
	}{
		{0, validFormat},
		{1, nil},
		{2, nil},
		{3, nil},
		{4, []byte("local\tbackup-server\ts3://bucket/prefix\thttps://backup.example\tus-east-1\n")},
		{4, []byte("disk\tfilesystem\tfilesystem://0123456789abcdef0123456789abcdef\t-\t-\n")},
		{5, nil},
		{6, []byte("^\\./proc(?:/|$)\n")},
	}
	for _, seed := range seeds {
		f.Add(seed.kind, seed.data)
	}
	f.Fuzz(func(t *testing.T, kind byte, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		limits := DefaultLimits()
		var canonical []byte
		var err error
		switch kind % 7 {
		case 0:
			var value RepositoryFormat
			value, err = ParseRepositoryFormat(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = value.MarshalText()
			}
		case 1:
			var value []IndexEntry
			value, err = ParseIndex(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = MarshalIndex(value)
			}
		case 2:
			var value []ObjectEntry
			value, err = ParseObjects(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = MarshalObjects(value)
			}
		case 3:
			var value []PackEntry
			value, err = ParsePacks(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = MarshalPacks(value)
			}
		case 4:
			var value []Mirror
			value, err = ParseMirrors(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = MarshalMirrors(value)
			}
		case 5:
			var value MetadataManifest
			value, err = ParseMetadataManifest(bytes.NewReader(data), limits)
			if err == nil {
				canonical, err = value.MarshalText()
			}
		case 6:
			var value Ignore
			value, err = ParseIgnore(bytes.NewReader(data), limits)
			if err == nil {
				patterns := value.Patterns()
				if len(patterns) != 0 {
					canonical = []byte(strings.Join(patterns, "\n") + "\n")
				}
				if !bytes.Equal(canonical, data) {
					// Blank ignore lines are explicitly insignificant.
					return
				}
			}
		}
		if err != nil {
			return
		}
		if !bytes.Equal(canonical, data) {
			t.Fatalf("parser accepted noncanonical bytes: kind=%d input=%q canonical=%q", kind%8, data, canonical)
		}
	})
}

func FuzzValidatePath(f *testing.F) {
	for _, seed := range []string{"./file", "./dir/file with spaces", "./こんにちは", "../escape", "./a/../b", "./a\x00b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 1<<16 {
			t.Skip()
		}
		_ = ValidatePath(path)
		_ = ValidateSymlinkTarget(path)
	})
}

func FuzzCanonicalObjectKeys(f *testing.F) {
	f.Add(strings.Repeat("0", 128), strings.Repeat("1", 32), strings.Repeat("2", 64))
	f.Fuzz(func(t *testing.T, hash, objectID, tip string) {
		if len(hash)+len(objectID)+len(tip) > 1<<16 {
			t.Skip()
		}
		_, _ = ObjectKey(hash, objectID)
		part := ManifestPart{ObjectID: objectID, Hash: hash}
		_, _ = MetadataPartKey(part)
		_, _ = MetadataManifestKey(tip, hash, objectID)
	})
}
