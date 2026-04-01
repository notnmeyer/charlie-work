#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-.}"

# package-lock.json: axios version is on the line after the "axios" key
check_axios_version_npm() {
    local lockfile="$1"
    if grep -A1 '"axios"' "$lockfile" | grep -qE "1\.14\.1|0\.30\.4"; then
        echo "[WARN] Malicious axios version (1.14.1 or 0.30.4) found in $lockfile"
    else
        echo "[OK]   No malicious axios version in $lockfile"
    fi
}

# yarn.lock: version appears as `version "x.y.z"` (v1) or `version: x.y.z` (berry)
check_axios_version_yarn() {
    local lockfile="$1"
    if grep -qE 'version:? "?(1\.14\.1|0\.30\.4)"?' "$lockfile"; then
        echo "[WARN] Malicious axios version (1.14.1 or 0.30.4) found in $lockfile"
    else
        echo "[OK]   No malicious axios version in $lockfile"
    fi
}

check_plain_crypto_js() {
    local lockfile="$1"
    if grep -q "plain-crypto-js" "$lockfile"; then
        echo "[WARN] plain-crypto-js found in $lockfile"
    else
        echo "[OK]   plain-crypto-js not found in $lockfile"
    fi
}

check_plain_crypto_js_installed() {
    local lockfile="$1"
    local module
    module="$(dirname "$lockfile")/node_modules/plain-crypto-js"
    if [[ -d "$module" ]]; then
        echo "[WARN] plain-crypto-js is installed at $module — POTENTIALLY AFFECTED"
    else
        echo "[OK]   plain-crypto-js not installed alongside $lockfile"
    fi
}

check_macos_persistence() {
    local cache_path="/Library/Caches/com.apple.act.mond"
    if [[ -e "$cache_path" ]]; then
        echo "[WARN] $cache_path exists — COMPROMISED"
        ls -la "$cache_path"
    else
        echo "[OK]   $cache_path not found"
    fi
}

echo "=== Axios supply chain attack check ==="
echo "Scanning: $DIR"
echo ""

found=0

while IFS= read -r -d '' lockfile; do
    found=1
    echo "--- $lockfile"
    case "$(basename "$lockfile")" in
        package-lock.json) check_axios_version_npm "$lockfile" ;;
        yarn.lock)         check_axios_version_yarn "$lockfile" ;;
    esac
    check_plain_crypto_js "$lockfile"
    check_plain_crypto_js_installed "$lockfile"
    echo ""
done < <(find "$DIR" \( -name "package-lock.json" -o -name "yarn.lock" \) -print0)

if [[ $found -eq 0 ]]; then
    echo "[SKIP] No package-lock.json or yarn.lock files found under $DIR"
fi

check_macos_persistence
