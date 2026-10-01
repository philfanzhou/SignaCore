#!/usr/bin/env bash
# Builds and runs a consumer against packages restored from a NuGet source.
#
# This is the only check that speaks for a consumer rather than for the build that produced the
# package: the artifacts come back from the feed, through a cache that has never held a SignaCore
# package, so nothing on the runner can make a broken or missing package look installable. The
# same script serves the pre-publish smoke (against the local pack output directory) and the
# post-publish verification (against NuGet.org itself).
#
# Usage: published-package-consumption.sh --version V --source URL --consumer DIR
#          [--attempts N] [--delay-seconds N]
set -euo pipefail

version=""
source_url=""
consumer=""
attempts=1
delay_seconds=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --source) source_url="${2:-}"; shift 2 ;;
    --consumer) consumer="${2:-}"; shift 2 ;;
    --attempts) attempts="${2:-}"; shift 2 ;;
    --delay-seconds) delay_seconds="${2:-}"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$version" || -z "$source_url" || -z "$consumer" ]]; then
  echo "Usage: published-package-consumption.sh --version V --source URL --consumer DIR" >&2
  exit 2
fi

if [[ ! "$attempts" =~ ^[0-9]+$ ]] || (( attempts < 1 )); then
  echo "The attempt budget must be a positive integer." >&2
  exit 2
fi

# Checked here rather than left to sleep: an unusable value would otherwise surface as an obscure
# error in the middle of the wait, after a push has already happened.
if [[ ! "$delay_seconds" =~ ^[0-9]+$ ]]; then
  echo "The retry delay must be a non-negative whole number of seconds." >&2
  exit 2
fi

consumer="$(cd "$consumer" && pwd)"

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT

export NUGET_PACKAGES="$workspace/nuget-cache"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=true

project="$workspace/consumer"
mkdir -p "$project"
cp "$consumer"/* "$project/"
printf '<Project />\n' > "$project/Directory.Build.props"
printf '<Project />\n' > "$project/Directory.Packages.props"

cat > "$project/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="release" value="$source_url" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF

for file in "$project"/*.csproj; do
  sed -i.bak "s/__SIGNACORE_VERSION__/$version/g" "$file"
  rm -f "$file.bak"
done

# The exact version is pinned by the consumer project, so the nuget.org fallback beside the
# release source cannot substitute a different build: against NuGet.org both sources are the same
# feed, and against a local pack directory the fallback only supplies the package's transitive
# dependencies, which the pinned version cannot pick from anywhere else.
#
# A push is visible to the feed's search and restore paths some time after it is accepted, so a
# first failure against NuGet.org is expected rather than a defect. The budget is finite: an
# indefinite wait would turn "never indexed" into a job that hangs until its timeout instead of
# reporting failure. 30 attempts x 30s covers a worst-case wait of 14.5 minutes, which stayed
# above the indexing latency observed on the ServiceMantle feed; a local source needs none of it.
restored=false
for attempt in $(seq 1 "$attempts"); do
  echo "Restore attempt $attempt of $attempts for version $version."
  if dotnet restore "$project" --configfile "$project/nuget.config"; then
    restored=true
    break
  fi

  if (( attempt < attempts )); then
    echo "Version $version is not restorable yet; waiting ${delay_seconds}s."
    sleep "$delay_seconds"
  fi
done

if [[ "$restored" != "true" ]]; then
  echo "Version $version did not become restorable from $source_url within $attempts attempts." >&2
  exit 1
fi

dotnet build "$project" --configuration Release --no-restore

resolved="$(python3 - "$project" <<'PY'
import json, pathlib, sys
assets = json.loads((pathlib.Path(sys.argv[1]) / "obj" / "project.assets.json").read_text())
print("\n".join(sorted(
    name for name in assets["libraries"] if name.startswith("SignaCore"))))
PY
)"
echo "Resolved SignaCore libraries:"
while IFS= read -r library; do
  [[ -n "$library" ]] || continue
  echo "  ${library}"
  if [[ "${library##*/}" != "$version" ]]; then
    echo "Consumer resolved $library instead of version $version." >&2
    exit 1
  fi
done <<< "$resolved"

echo "Starting the consumer against the restored packages."
dotnet run --project "$project" --configuration Release --no-build --no-restore &
consumer_pid=$!

# The consumer's host starts and immediately begins waiting for shutdown; a few seconds of life
# prove the resolved package boots as an ASP.NET Core application.
sleep 5
if ! kill -0 "$consumer_pid" 2>/dev/null; then
  wait "$consumer_pid" || true
  echo "The consumer exited before the smoke window elapsed." >&2
  exit 1
fi
kill "$consumer_pid" 2>/dev/null || true
wait "$consumer_pid" 2>/dev/null || true

echo "Package consumption verified for version $version from $source_url."
