#!/usr/bin/env bash
set -euo pipefail

DIR="${1:-.}"

warnings=()

warn() {
    warnings+=("$1")
    printf 'x'
}

ok() {
    printf '.'
}

# package-lock.json: axios version is on the line after the "axios" key
check_axios_version_npm() {
    local lockfile="$1"
    if grep -A1 '"axios"' "$lockfile" | grep -qE "1\.14\.1|0\.30\.4"; then
        warn "[WARN] Malicious axios version (1.14.1 or 0.30.4) found in $lockfile"
    else
        ok
    fi
}

# yarn.lock: version appears as `version "x.y.z"` (v1) or `version: x.y.z` (berry)
check_axios_version_yarn() {
    local lockfile="$1"
    if grep -A2 '^"*axios@' "$lockfile" | grep -qE 'version:? "?(1\.14\.1|0\.30\.4)"?'; then
        warn "[WARN] Malicious axios version (1.14.1 or 0.30.4) found in $lockfile"
    else
        ok
    fi
}

check_plain_crypto_js() {
    local lockfile="$1"
    if grep -q "plain-crypto-js" "$lockfile"; then
        warn "[WARN] plain-crypto-js found in $lockfile"
    else
        ok
    fi
}

check_plain_crypto_js_installed() {
    local lockfile="$1"
    local module
    module="$(dirname "$lockfile")/node_modules/plain-crypto-js"
    if [[ -d "$module" ]]; then
        warn "[WARN] plain-crypto-js is installed at $module — POTENTIALLY AFFECTED"
    else
        ok
    fi
}

check_rat_artifacts() {
    local os
    os="$(uname -s)"
    case "$os" in
        Darwin)
            local path="/Library/Caches/com.apple.act.mond"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (macOS)"
            else
                ok
            fi
            ;;
        Linux)
            local path="/tmp/ld.py"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (Linux)"
            else
                ok
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            local path="${PROGRAMDATA:-C:\\ProgramData}\\wt.exe"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (Windows)"
            else
                ok
            fi
            ;;
        *)
            ok
            ;;
    esac
}

echo "=== charlie work ==="
echo "Scanning: $DIR"
echo ""

found=0


printf "Scanning lock files: "
while IFS= read -r -d '' lockfile; do
    found=1
    case "$(basename "$lockfile")" in
        package-lock.json) check_axios_version_npm "$lockfile" ;;
        yarn.lock)         check_axios_version_yarn "$lockfile" ;;
    esac
    check_plain_crypto_js "$lockfile"
    check_plain_crypto_js_installed "$lockfile"
done < <(find "$DIR" \( -name "package-lock.json" -o -name "yarn.lock" \) -print0)

if [[ $found -eq 0 ]]; then
    printf "No package-lock.json or yarn.lock files found under %s" "$DIR"
fi

echo; printf "Checking for RAT artifacts: "
check_rat_artifacts

echo ""

if [[ ${#warnings[@]} -gt 0 ]]; then
    echo ""
    for w in "${warnings[@]}"; do
        echo "$w"
    done
else
    echo; echo "✅ No signs of compromise."
fi
