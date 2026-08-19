#!/usr/bin/env bash
#
# Pull container images, retrying only the failures that a retry can actually fix.
#
# Anonymous pulls intermittently fail with "unauthorized: authentication required" or a rate-limit
# message. That fails the job for a reason unrelated to the change under test, and the message
# points at credentials rather than at the registry being unhappy. Everything pulled here is
# public, so those responses are treated as transient. Anything else fails on the first attempt,
# so a missing or misspelled image is still reported immediately.
set -euo pipefail

readonly attempts=3

if [ "$#" -eq 0 ]; then
  echo "usage: docker-pull.sh IMAGE [IMAGE...]" >&2
  exit 2
fi

for image in "$@"; do
  echo "::group::docker pull ${image}"
  started=$SECONDS

  for attempt in $(seq 1 "$attempts"); do
    if pull_output=$(docker pull "$image" 2>&1); then
      printf '%s\n' "$pull_output"
      echo "Pulled ${image} in $((SECONDS - started))s on attempt ${attempt}."
      break
    fi

    printf '%s\n' "$pull_output"

    if ! printf '%s' "$pull_output" | grep -Eqi \
      'unauthorized|authentication required|toomanyrequests|rate limit|timeout|temporary failure|connection reset|connection refused|i/o timeout|TLS handshake|EOF'; then
      echo "::endgroup::"
      echo "docker pull ${image} failed for a reason a retry will not fix." >&2
      exit 1
    fi

    if [ "$attempt" -eq "$attempts" ]; then
      echo "::endgroup::"
      echo "docker pull ${image} did not succeed after ${attempts} attempts." >&2
      exit 1
    fi

    delay=$((attempt * 10))
    echo "docker pull ${image} hit a transient registry error; retrying in ${delay}s." >&2
    sleep "$delay"
  done

  echo "::endgroup::"
done
