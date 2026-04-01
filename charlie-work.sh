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

check_axios_installed() {
    local lockfile="$1"
    local pkg
    pkg="$(dirname "$lockfile")/node_modules/axios/package.json"
    if [[ ! -f "$pkg" ]]; then
        ok
        return
    fi
    if grep -A1 '"version"' "$pkg" | grep -qE "1\.14\.1|0\.30\.4"; then
        warn "[WARN] Malicious axios version (1.14.1 or 0.30.4) installed at $(dirname "$pkg")"
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

check_file_hash() {
    local path="$1" expected="$2"
    local actual
    if command -v shasum &>/dev/null; then
        actual="$(shasum -a 256 "$path" | awk '{print $1}')"
    elif command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "$path" | awk '{print $1}')"
    else
        return  # can't verify, skip silently
    fi
    if [[ "$actual" == "$expected" ]]; then
        warn "[WARN] $path hash matches known RAT payload — COMPROMISED"
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
            local hash="92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (macOS)"
                check_file_hash "$path" "$hash"
            else
                ok
            fi
            ;;
        Linux)
            local path="/tmp/ld.py"
            local hash="fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (Linux)"
                check_file_hash "$path" "$hash"
            else
                ok
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            local path="${PROGRAMDATA:-C:\\ProgramData}\\wt.exe"
            local hash="617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"
            if [[ -e "$path" ]]; then
                warn "[WARN] $path exists — COMPROMISED (Windows)"
                check_file_hash "$path" "$hash"
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
    check_axios_installed "$lockfile"
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
