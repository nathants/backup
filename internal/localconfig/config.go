package localconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

const maximumConfigBytes = 16 << 20

var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)

type Mirror struct {
	Canonical     format.Mirror
	WriterProfile string
	ReaderProfile string
	CAFile        string
}

type Config struct {
	GitRemote string
	Branch    string
	Mirrors   []Mirror
}

func Load(path string) (Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, err
	}
	fd, err := unix.Open(absolute, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, fmt.Errorf("open trusted config: %w", err)
	}
	file := os.NewFile(uintptr(fd), absolute)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return Config{}, fmt.Errorf("trusted config must be a regular file without group/other write permissions")
	}
	if info.Size() < 1 || info.Size() > maximumConfigBytes {
		return Config{}, fmt.Errorf("trusted config size is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read trusted config: %w", err)
	}
	if len(data) != int(info.Size()) {
		return Config{}, fmt.Errorf("trusted config size changed while reading")
	}
	return parse(data)
}

func parse(data []byte) (Config, error) {
	if len(data) == 0 || len(data) > maximumConfigBytes || data[len(data)-1] != '\n' || !utf8.Valid(data) || strings.ContainsAny(string(data), "\x00\r") {
		return Config{}, fmt.Errorf("trusted config must be bounded UTF-8/LF text ending in LF")
	}
	config := Config{}
	seenGit, seenBranch := false, false
	seenMirrors := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if line == "" {
			return Config{}, fmt.Errorf("trusted config line %d is blank", lineNumber)
		}
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "git-remote":
			if len(fields) != 2 || seenGit || fields[1] == "" || strings.ContainsAny(fields[1], "\r\n\x00") {
				return Config{}, fmt.Errorf("invalid git-remote row at line %d", lineNumber)
			}
			seenGit = true
			config.GitRemote = fields[1]
		case "branch":
			if len(fields) != 2 || seenBranch || !branchPattern.MatchString(fields[1]) || strings.Contains(fields[1], "..") || strings.Contains(fields[1], "//") || strings.HasSuffix(fields[1], "/") {
				return Config{}, fmt.Errorf("invalid branch row at line %d", lineNumber)
			}
			seenBranch = true
			config.Branch = fields[1]
		case "mirror":
			if len(fields) != 9 {
				return Config{}, fmt.Errorf("mirror row at line %d has %d fields, expected 9", lineNumber, len(fields))
			}
			canonical := format.Mirror{Name: fields[1], Kind: fields[2], S3URL: fields[3], Endpoint: fields[4], Region: fields[5]}
			if _, err := format.MarshalMirrors([]format.Mirror{canonical}); err != nil {
				return Config{}, fmt.Errorf("invalid mirror row at line %d: %w", lineNumber, err)
			}
			if seenMirrors[canonical.Name] {
				return Config{}, fmt.Errorf("duplicate mirror %q", canonical.Name)
			}
			seenMirrors[canonical.Name] = true
			for index := 6; index <= 8; index++ {
				if fields[index] == "" || strings.ContainsAny(fields[index], "\x00\t\r\n") {
					return Config{}, fmt.Errorf("mirror %q has an invalid local binding", canonical.Name)
				}
			}
			config.Mirrors = append(config.Mirrors, Mirror{Canonical: canonical, WriterProfile: fields[6], ReaderProfile: fields[7], CAFile: fields[8]})
		default:
			return Config{}, fmt.Errorf("unknown trusted config row %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	if !seenGit || !seenBranch || len(config.Mirrors) == 0 {
		return Config{}, fmt.Errorf("trusted config requires git-remote, branch, and at least one mirror")
	}
	if !sort.SliceIsSorted(config.Mirrors, func(left, right int) bool {
		return config.Mirrors[left].Canonical.Name < config.Mirrors[right].Canonical.Name
	}) {
		return Config{}, fmt.Errorf("trusted config mirror rows are not sorted by name")
	}
	return config, nil
}

func (config Config) RequireCanonicalMirrors(canonical []format.Mirror) error {
	if len(canonical) != len(config.Mirrors) {
		return fmt.Errorf("canonical and pinned mirror counts differ")
	}
	for index, mirror := range canonical {
		if config.Mirrors[index].Canonical != mirror {
			return fmt.Errorf("canonical mirror %q does not match its trusted local pin", mirror.Name)
		}
	}
	return nil
}
