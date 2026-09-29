#!/usr/bin/env python3
"""Run a command and drain its Linux descendants before authorizing cleanup."""

import argparse
import ctypes
import math
import os
import pathlib
import signal
import subprocess
import sys
import time


def duration(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be finite and positive")
    return seconds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", required=True, type=duration)
    parser.add_argument("--kill-after", default=30, type=duration)
    parser.add_argument("--drained", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or os.path.lexists(args.drained):
        parser.error("command and a new drain-marker path are required")

    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_CHILD_SUBREAPER: orphaned descendants reparent here, including
    # descendants that created their own process groups or sessions.
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")

    received = 0

    def interrupted(number, _frame):
        nonlocal received
        if not received:
            received = number

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    process = None
    terminated = set()

    def reap():
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            if pid == 0:
                return False
            terminated.discard(pid)
            if process is not None and pid == process.pid:
                process.returncode = (
                    os.WEXITSTATUS(status)
                    if os.WIFEXITED(status)
                    else -os.WTERMSIG(status)
                )

    def drain():
        kill_at = time.monotonic() + args.kill_after
        deadline = kill_at + 10
        children = pathlib.Path(f"/proc/self/task/{os.getpid()}/children")
        while time.monotonic() < deadline:
            if reap():
                return True
            force = time.monotonic() >= kill_at
            # This single-threaded process is the sole reaper. Between this
            # snapshot and signaling, exited children remain unreaped zombies,
            # so their PIDs cannot be reused for unrelated processes.
            for pid in map(int, children.read_text().split()):
                if force or pid not in terminated:
                    try:
                        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    terminated.add(pid)
            time.sleep(0.02)
        return reap()

    status = 125
    try:
        process = subprocess.Popen(command, start_new_session=True)
        deadline = time.monotonic() + args.timeout
        while True:
            reap()
            if received:
                status = 128 + received
                break
            if process.returncode is not None:
                status = process.returncode
                if status < 0:
                    status = 128 - status
                break
            if time.monotonic() >= deadline:
                print("command timed out; draining descendants", file=sys.stderr)
                status = 124
                break
            time.sleep(0.02)
    except Exception as error:
        print(f"run command: {error}", file=sys.stderr)
    finally:
        try:
            if not drain():
                raise RuntimeError("descendants did not exit after SIGKILL")
            with open(args.drained, "x", encoding="ascii") as marker:
                marker.write("drained\n")
        except Exception as error:
            print(f"process cleanup unconfirmed: {error}", file=sys.stderr)
            status = 125
    return 128 + received if received else status


if __name__ == "__main__":
    sys.exit(main())
