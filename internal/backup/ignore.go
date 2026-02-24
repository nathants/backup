package backup

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Ignore struct {
	raw     []string
	regexes []*regexp.Regexp
}

func LoadIgnore(path string) (Ignore, error) {
	file, err := os.Open(path)
	if err != nil {
		return Ignore{}, err
	}
	defer func() { _ = file.Close() }()
	var lines []string
	var regexes []*regexp.Regexp
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		re, err := regexp.Compile(line)
		if err != nil {
			return Ignore{}, fmt.Errorf("invalid ignore regex %q: %w", line, err)
		}
		regexes = append(regexes, re)
	}
	err = scanner.Err()
	if err != nil {
		return Ignore{}, err
	}
	return Ignore{raw: lines, regexes: regexes}, nil
}

func (ignore Ignore) Matches(path string) bool {
	for _, re := range ignore.regexes {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
