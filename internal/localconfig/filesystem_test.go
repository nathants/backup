package localconfig

import (
	"strings"
	"testing"

	"backup/internal/format"
)

func TestFilesystemBindingPinsIdentityNotMountPath(t *testing.T) {
	identity := "filesystem://" + strings.Repeat("a", 32)
	data := "git-remote\t/tmp/primary.git\nbranch\tmain\nmirror\tdisk\tfilesystem\t" + identity + "\t-\t-\t/home/user/mounted disk/backup\t/home/user/mounted disk\n"
	config, err := parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	mirror := config.Mirrors[0]
	if mirror.Profile != "" || mirror.CAFile != "" || mirror.Directory != "/home/user/mounted disk/backup" || mirror.Mount != "/home/user/mounted disk" {
		t.Fatalf("binding: %+v", mirror)
	}
	canonical := []format.Mirror{mirror.Canonical}
	moved, err := parse([]byte(strings.ReplaceAll(data, "/home/user/mounted disk", "/media/other")))
	if err != nil {
		t.Fatal(err)
	}
	if err := moved.RequireCanonicalMirrors(canonical); err != nil {
		t.Fatalf("path was canonical identity: %v", err)
	}
	wrong := canonical
	wrong[0].S3URL = "filesystem://" + strings.Repeat("b", 32)
	if err := moved.RequireCanonicalMirrors(wrong); err == nil {
		t.Fatal("changed store identity accepted")
	}
	for _, bad := range []string{
		strings.Replace(data, identity, "file:///tmp/store", 1),
		strings.Replace(data, identity, strings.ToUpper(identity), 1),
		strings.Replace(data, "\t-\t-\t", "\thttps://host\t-\t", 1),
		strings.Replace(data, "\t-\t-\t", "\t-\tus-east-1\t", 1),
		strings.Replace(data, "/home/user/mounted disk/backup", "~/mounted disk/backup", 1),
		strings.Replace(data, "/home/user/mounted disk/backup", "/other/store", 1),
		strings.Replace(data, "/home/user/mounted disk/backup", "/home/user/mounted disk/../backup", 1),
		strings.Replace(data, "\t/home/user/mounted disk\n", "\t/\n", 1),
		data + "mirror\tsecond\tfilesystem\t" + identity + "\t-\t-\t/other\t-\n",
		data + "mirror\tsecond\tfilesystem\tfilesystem://" + strings.Repeat("b", 32) + "\t-\t-\t/home/user/mounted disk/backup/nested\t-\n",
	} {
		if _, err := parse([]byte(bad)); err == nil {
			t.Fatalf("invalid filesystem binding accepted: %q", bad)
		}
	}
}
