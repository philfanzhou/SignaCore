#!/usr/bin/env python3
"""Resolve a fixed official Linux/amd64 image with bounded, fail-closed recovery."""
import json
import os
import re
import signal
import subprocess
import sys
import time

PROFILES = {
    "node": ("24-alpine", "sha256:83f1c388c31fb2e51f7cbd4dea949b96260798c98f206e8e4696bc93bd964e3a"),
    "postgres": ("15-alpine", "sha256:25d430274d8a31184f9435cc5b2f56aff254952065bbbcac0c51acedb5a1d1e7"),
}
SOURCES = ("public.ecr.aws/docker/library", "docker.io/library")
PULL_TIMEOUT = 180
INSPECT_TIMEOUT = 15
ATTEMPTS = 2
RETRY_DELAY = 5
HARD_ERRORS = re.compile(
    r"manifest unknown|manifest.*not found|name unknown|invalid reference|invalid argument|"
    r"unknown flag|unsupported platform|no matching manifest|insufficient.scope|"
    r"permission denied|cannot connect to the docker daemon|is the docker daemon running|"
    r"digest mismatch|digest verification|content.*mismatch|checksum|unauthorized.*incorrect",
    re.I,
)
TRANSIENT_ERRORS = re.compile(
    r"\b429\b|toomanyrequests|rate.?limit|data limit exceeded|"
    r"unauthorized: authentication required|anonymous.*authentication required|"
    r"connection reset|connection refused|temporary failure in name resolution|"
    r"i/o timeout|TLS handshake timeout|context deadline exceeded|\bEOF\b|"
    r"net/http:.*timeout|request.*timed out|connection.*timed out",
    re.I,
)


class ResolutionError(Exception):
    pass


class Cancelled(Exception):
    pass


def terminate(signum, frame):
    raise Cancelled()


def command(args, timeout):
    # Own the child process group so cancellation and timeouts leave no pull running.
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
        return child.returncode, stdout, stderr
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate()
        raise


def references(profile):
    tag, digest = PROFILES[profile]
    return tuple(f"{source}/{profile}:{tag}@{digest}" for source in SOURCES)


def diagnose(profile, source, attempt, category):
    # Registry output can contain credentials; never echo it, exceptions, or environment values.
    print(f"official-image profile={profile} source={source} attempt={attempt} category={category}",
          file=sys.stderr)


def verify(profile, reference):
    try:
        code, stdout, _ = command(["docker", "image", "inspect", reference], INSPECT_TIMEOUT)
        if code != 0:
            raise ResolutionError()
        images = json.loads(stdout)
        if len(images) != 1:
            raise ResolutionError()
        image = images[0]
        digest = PROFILES[profile][1]
        repository = reference.split(":", 1)[0]
        accepted = {f"{repository}@{digest}"}
        if repository.startswith("docker.io/library/"):
            accepted.update((f"{profile}@{digest}", f"library/{profile}@{digest}"))
        if (image.get("Os") != "linux" or image.get("Architecture") != "amd64"
                or not accepted.intersection(image.get("RepoDigests") or [])):
            raise ResolutionError()
    except (subprocess.TimeoutExpired, ValueError, TypeError, KeyError, AttributeError):
        raise ResolutionError() from None


def resolve(profile):
    for source_index, reference in enumerate(references(profile)):
        source = "primary" if source_index == 0 else "secondary"
        for attempt in range(1, ATTEMPTS + 1):
            try:
                code, stdout, stderr = command(
                    ["docker", "pull", "--platform", "linux/amd64", reference], PULL_TIMEOUT)
            except subprocess.TimeoutExpired:
                category = "timeout"
            else:
                if code == 0:
                    try:
                        verify(profile, reference)
                    except ResolutionError:
                        diagnose(profile, source, attempt, "validation-failed")
                        raise
                    diagnose(profile, source, attempt, "success")
                    return reference
                output = stdout + stderr
                if HARD_ERRORS.search(output) or not TRANSIENT_ERRORS.search(output):
                    diagnose(profile, source, attempt, "permanent-or-unknown")
                    raise ResolutionError()
                category = "transient"
            diagnose(profile, source, attempt, category)
            if attempt < ATTEMPTS:
                time.sleep(RETRY_DELAY)
    raise ResolutionError()


def main(argv):
    if len(argv) != 1 or argv[0] not in PROFILES:
        print("usage: resolve_official_image.py node|postgres", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, terminate)
    try:
        reference = resolve(argv[0])
        print(reference)
        return 0
    except (KeyboardInterrupt, Cancelled):
        print("official-image category=cancelled", file=sys.stderr)
        return 130
    except (ResolutionError, OSError):
        print("official-image category=failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
