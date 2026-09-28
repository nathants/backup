package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the real runner with scripted provider/process boundaries. GNU
// timeout still enforces deadlines; only their durations are shortened.
func TestGitPrimaryRunnerLifecycle(t *testing.T) {
	for _, scenario := range []string{
		"success", "existing-bucket", "existing-table", "inventory-error",
		"test-failure", "partial-create", "test-timeout", "interrupt", "terminate", "orphan",
		"cleanup-failure", "cleanup-timeout", "cleanup-inventory-error",
		"helper-changed", "helper-status-error",
	} {
		t.Run(scenario, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Fatal(err)
			}
			timeout, err := exec.LookPath("timeout")
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			bin := filepath.Join(directory, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			fixture := filepath.Join(bin, "fixture")
			writeFile(t, fixture, []byte("#!"+python+"\n"+gitPrimaryRunnerFixture), 0o700)
			for _, name := range []string{"aws", "libaws", "go", "git", "timeout"} {
				if err := os.Symlink(fixture, filepath.Join(bin, name)); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.CommandContext(t.Context(), "bash", "./git-remote.sh")
			command.Env = cleanEnvironment(map[string]string{
				"PATH":                bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"LIBAWS_TEST_ACCOUNT": "123456789012", "AWS_REGION": "us-east-1",
				"AWS_ACCESS_KEY_ID": "synthetic", "AWS_SECRET_ACCESS_KEY": "synthetic",
				"BACKUP_CONTRACT_EVIDENCE_DIR": filepath.Join(directory, "evidence"),
				"RUNNER_FIXTURE_DIRECTORY":     directory, "RUNNER_FIXTURE_SCENARIO": scenario,
				"RUNNER_FIXTURE_TIMEOUT": timeout,
			})
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
			command.WaitDelay = time.Second
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			var signalDone chan error
			if scenario == "interrupt" || scenario == "terminate" {
				signalDone = make(chan error, 1)
				go func() {
					deadline := time.Now().Add(5 * time.Second)
					for time.Now().Before(deadline) {
						if _, err := os.Stat(filepath.Join(directory, "started")); err == nil {
							signal := syscall.SIGINT
							if scenario == "terminate" {
								signal = syscall.SIGTERM
							}
							signalDone <- command.Process.Signal(signal)
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
					signalDone <- os.ErrDeadlineExceeded
				}()
			}
			runErr := command.Wait()
			if signalDone != nil {
				if err := <-signalDone; err != nil {
					t.Fatal(err)
				}
			}
			if (runErr == nil) != (scenario == "success") {
				t.Fatalf("runner result: %v\n%s", runErr, output.String())
			}
			if scenario == "interrupt" || scenario == "terminate" {
				wantStatus := 130
				if scenario == "terminate" {
					wantStatus = 143
				}
				if exit, ok := errors.AsType[*exec.ExitError](runErr); !ok || exit.ExitCode() != wantStatus {
					t.Fatalf("lost signal exit status %d: %v", wantStatus, runErr)
				}
			}
			data, err := os.ReadFile(filepath.Join(directory, "events"))
			if err != nil {
				t.Fatal(err)
			}
			var created, buckets, tables []string
			for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
				var event []string
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				switch event[0] {
				case "create":
					created = append(created, event[1])
				case "bucket-delete":
					buckets = append(buckets, event[1])
				case "table-delete":
					tables = append(tables, event[1])
				case "unsafe-cleanup":
					t.Fatal("cleanup raced a live test descendant")
				}
			}
			guarded := scenario == "existing-bucket" || scenario == "existing-table" || scenario == "inventory-error"
			if guarded {
				if len(created)+len(buckets)+len(tables) != 0 {
					t.Fatalf("failed preflight allowed mutation: %s", data)
				}
				return
			}
			want := 1
			if scenario == "success" || strings.HasPrefix(scenario, "cleanup-") || strings.HasPrefix(scenario, "helper-") {
				want = 2
			}
			wantTables := created
			if scenario == "partial-create" {
				wantTables = nil
			}
			if len(created) != want || strings.Join(wantTables, "\n") != strings.Join(tables, "\n") {
				t.Fatalf("table cleanup missed an attempted create: %s\n%s", data, output.String())
			}
			if scenario == "cleanup-inventory-error" {
				if len(buckets) != 0 {
					t.Fatalf("failed ownership inventory authorized deletion: %s", data)
				}
			} else if strings.Join(created, "\n") != strings.Join(buckets, "\n") {
				t.Fatalf("bucket cleanup missed an attempted create: %s\n%s", data, output.String())
			}
			if !strings.Contains(output.String(), "evidence:") {
				t.Fatalf("runner omitted retained evidence location: %s", output.String())
			}
		})
	}
}

const gitPrimaryRunnerFixture = `import json, os, pathlib, re, signal, subprocess, sys, time
root = pathlib.Path(os.environ['RUNNER_FIXTURE_DIRECTORY'])
scenario = os.environ['RUNNER_FIXTURE_SCENARIO']
tool = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
def event(*values):
    with (root/'events').open('a') as f:
        f.write(json.dumps(values)+'\n')
def state(kind, name):
    return root/(kind+'-'+name)
def hang():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
if tool == 'timeout':
    short = []
    for arg in args:
        if arg.startswith('--kill-after='):
            arg = '--kill-after=0.1s'
        elif arg == '35m':
            arg = '0.4s' if scenario == 'test-timeout' else '10s'
        elif arg in ('2m', '5m'):
            arg = '0.4s'
        short.append(arg)
    os.execv(os.environ['RUNNER_FIXTURE_TIMEOUT'], ['timeout']+short)
if tool == 'git':
    if 'status' in args and scenario == 'helper-status-error' and (root/'started').exists():
        sys.exit(1)
    if 'status' not in args:
        print(('b' if scenario == 'helper-changed' and (root/'started').exists() else 'a')*40)
    sys.exit(0)
if tool == 'go':
    if args[0] == 'build':
        sys.exit(0)
    name = os.environ.get('BACKUP_GIT_REMOTE_RESOURCE', 'backup-git-test-'+'f'*32)
    evidence, = (root/'evidence').glob('git-primary.*')
    mode = 'race' if os.environ.get('GOFLAGS') == '-race' else 'normal'
    if mode+'\t'+name not in (evidence/'resources.tsv').read_text().splitlines():
        raise RuntimeError('creation started without recorded cleanup intent')
    event('create', name)
    state('bucket', name).touch()
    if scenario == 'partial-create':
        sys.exit(1)
    state('table', name).touch()
    (root/'started').touch()
    if scenario in ('interrupt', 'terminate', 'test-timeout'):
        hang()
    if scenario == 'orphan':
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3600)'])
        (root/'orphan').write_text(str(child.pid))
        sys.exit(1)
    if scenario == 'test-failure':
        sys.exit(1)
    print('--- PASS: TestAWSGitRemoteKeychains (0.01s)')
    sys.exit(0)
if tool == 'aws':
    if args[:2] == ['sts', 'get-caller-identity']:
        print('123456789012')
        sys.exit(0)
    if args[:2] in (['s3api', 'list-buckets'], ['dynamodb', 'list-tables']):
        kind = 'bucket' if args[0] == 's3api' else 'table'
        query = args[args.index('--query')+1]
        name = re.search(r"backup-git-test-[0-9a-f]{32}", query).group(0)
        event('inventory', kind, name)
        if scenario == 'inventory-error' or (scenario == 'cleanup-inventory-error' and kind == 'bucket' and state(kind, name).exists()):
            sys.exit(1)
        if scenario == 'existing-'+kind or state(kind, name).exists():
            print(name)
        sys.exit(0)
    if args[:3] == ['s3api', 'wait', 'bucket-not-exists']:
        sys.exit(int(state('bucket', args[args.index('--bucket')+1]).exists()))
    if args[:3] == ['dynamodb', 'wait', 'table-not-exists']:
        sys.exit(int(state('table', args[args.index('--table-name')+1]).exists()))
    if args[:2] == ['dynamodb', 'delete-table']:
        name = args[args.index('--table-name')+1]
        event('table-delete', name)
        state('table', name).unlink(missing_ok=True)
        sys.exit(0)
if tool == 'libaws' and args[0] == 's3-rm-bucket':
    name = args[1]
    event('bucket-delete', name)
    if (root/'orphan').exists():
        pid = (root/'orphan').read_text()
        try:
            if pathlib.Path('/proc/'+pid+'/stat').read_text().split()[2] != 'Z':
                event('unsafe-cleanup')
        except FileNotFoundError:
            pass
    if scenario == 'cleanup-failure':
        sys.exit(1)
    if scenario == 'cleanup-timeout':
        hang()
    state('bucket', name).unlink(missing_ok=True)
    sys.exit(0)
raise RuntimeError((tool, args))
`

func TestGitPrimaryContractRequiresRunner(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"", "production-bucket"} {
		command := exec.CommandContext(t.Context(), binary, "-test.run=^TestAWSGitRemoteKeychains$")
		command.Env = cleanEnvironment(map[string]string{
			"BACKUP_GIT_REMOTE_CONTRACT": "1", "BACKUP_GIT_REMOTE_RESOURCE": resource,
			"LIBAWS_TEST_ACCOUNT": "123456789012", "PATH": t.TempDir(),
		})
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "runner-owned scratch resource required") {
			t.Fatalf("unguarded resource %q did not fail before provider access: %v: %s", resource, err, output)
		}
	}
}
