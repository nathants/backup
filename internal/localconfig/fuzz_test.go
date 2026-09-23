package localconfig

import (
	"testing"

	"backup/internal/format"
)

func FuzzTrustedConfigParser(f *testing.F) {
	f.Add([]byte("git-remote\t/path/to/metadata.git\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://bucket/prefix\thttps://backup.example\tus-east-1\tbackup\t-\n"))
	f.Add([]byte("branch\tmain\n"))
	f.Add([]byte("git-remote\t/path/to/metadata.git\nbranch\tmain\nmirror\tdisk\tfilesystem\tfilesystem://0123456789abcdef0123456789abcdef\t-\t-\t/tmp/disk/store\t/tmp/disk\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		config, err := parse(data)
		if err != nil {
			return
		}
		mirrors := make([]format.Mirror, len(config.Mirrors))
		for index := range config.Mirrors {
			mirrors[index] = config.Mirrors[index].Canonical
		}
		if err := config.RequireCanonicalMirrors(mirrors); err != nil {
			t.Fatalf("accepted config disagrees with its own canonical mirrors: %v", err)
		}
	})
}
