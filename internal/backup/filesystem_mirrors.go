package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"backup/internal/format"
	"backup/internal/localconfig"
)

func filesystemSourceExclusions(root string, config localconfig.Config) ([]string, error) {
	// Resolve the already-openable source root once; mirror paths themselves are
	// canonical no-follow paths, and need not be available while planning.
	source, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	var excluded []string
	for _, mirror := range config.Mirrors {
		if mirror.Canonical.Kind != format.MirrorFilesystem {
			continue
		}
		directory := mirror.Directory
		if source == directory || strings.HasPrefix(source, directory+"/") {
			return nil, fmt.Errorf("source root is inside filesystem mirror %s", mirror.Canonical.Name)
		}
		relative, err := filepath.Rel(source, directory)
		if err != nil {
			return nil, err
		}
		if relative == ".." || strings.HasPrefix(relative, "../") {
			continue
		}
		excluded = append(excluded, "./"+relative)
	}
	return excluded, nil
}

func (run *runtime) filesystemScanIgnore(ignore format.Ignore) (format.Ignore, error) {
	config := run.config
	// Local preparation still works without a config. If one has been supplied,
	// validate it without credentials or network access before using exclusions.
	if run.preparation != nil && run.preparation.GitRemote == "" {
		var err error
		config, err = localconfig.Load(run.options.ConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return format.Ignore{}, err
		}
	}
	paths, err := filesystemSourceExclusions(run.options.Root, config)
	if err != nil {
		return format.Ignore{}, err
	}
	patterns := ignore.Patterns()
	for _, path := range paths {
		patterns = append(patterns, "^"+regexp.QuoteMeta(path)+"(/|$)")
		if err := run.reportf("filesystem-mirror-excluded\t%s\n", terminalEscape(path)); err != nil {
			return format.Ignore{}, err
		}
	}
	if len(paths) == 0 {
		return ignore, nil
	}
	return format.ParseIgnore(strings.NewReader(strings.Join(patterns, "\n")+"\n"), configurationLimits("ignore"))
}

func (run *runtime) requirePlanOutsideFilesystemMirrors(plan *stagedPlan, config localconfig.Config) error {
	paths, err := filesystemSourceExclusions(run.options.Root, config)
	if err != nil || len(paths) == 0 || plan == nil {
		return err
	}
	file, err := run.openStaged(plan.IndexFile.RelativePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return format.WalkIndex(file, format.DefaultLimits(), func(entry format.IndexEntry) error {
		for _, path := range paths {
			if entry.Path == path || strings.HasPrefix(entry.Path, path+"/") {
				return fmt.Errorf("add plan contains filesystem destination path %q; run add again before commit", entry.Path)
			}
		}
		return nil
	})
}
