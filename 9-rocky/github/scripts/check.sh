#!/bin/bash
#
# Dependency Check Script for GitHub Actions Runner
# This script should be run during Docker image build to verify all required dependencies
# are installed for the GitHub Actions Runner (dotnet Core 6.0)
#
# Usage: <script> [RUNNER_ROOT]
#   RUNNER_ROOT - Runner installation directory (default: /usr/local/runner)
#
# Exit codes:
#   0 - All dependencies satisfied
#   1 - Missing dependencies or tools

set -e

RUNNER_ROOT="${1:-/usr/local/runner}"

# Check if Runner.Listener binary exists
LISTENER_BIN="$RUNNER_ROOT/bin/Runner.Listener"
if [ ! -f "$LISTENER_BIN" ]; then
    echo "ERROR: Runner.Listener binary not found: $LISTENER_BIN"
    echo "Please ensure the GitHub Actions Runner is installed at: $RUNNER_ROOT"
    exit 1
fi

if [ ! -x "$LISTENER_BIN" ]; then
    echo "ERROR: Runner.Listener is not executable: $LISTENER_BIN"
    exit 1
fi

command -v ldd >/dev/null
if [ $? -ne 0 ]; then
    echo "Can not find 'ldd'. Please install 'ldd' and try again."
    exit 1
fi

# Check dotnet Core 6.0 libraries
BIN_DIR="$RUNNER_ROOT/bin"
if [ ! -d "$BIN_DIR" ]; then
    echo "ERROR: Runner bin directory not found: $BIN_DIR"
    echo "Please ensure the GitHub Actions Runner is installed at: $RUNNER_ROOT"
    exit 1
fi

LIBRARIES=(
    "libcoreclr.so"
    "libSystem.Security.Cryptography.Native.OpenSsl.so"
    "libSystem.IO.Compression.Native.so"
)

for lib in "${LIBRARIES[@]}"; do
    lib_path="$BIN_DIR/$lib"

    if [ ! -f "$lib_path" ]; then
        echo "Library not found: $lib"
        exit 1
    fi

    if ldd "$lib_path" 2>&1 | grep -q "not found"; then
        echo "Dependencies is missing for Dotnet Core 6.0 in $lib_path"
        exit 1
    fi
done

if ! [ -x "$(command -v ldconfig)" ]; then
    LDCONFIG_COMMAND="/sbin/ldconfig"
    if ! [ -x "$LDCONFIG_COMMAND" ]; then
        echo "Can not find 'ldconfig' in PATH and '/sbin/ldconfig' doesn't exists either. Please install 'ldconfig' and try again."
        exit 1
    fi
else
    LDCONFIG_COMMAND="ldconfig"
fi

libpath=${LD_LIBRARY_PATH:-}
$LDCONFIG_COMMAND -NXv ${libpath//:/ } 2>&1 | grep libicu >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Libicu's dependencies is missing for Dotnet Core 6.0"
    exit 1
fi
