#!/usr/bin/env bats

setup() {
    SCRIPT="$BATS_TEST_DIRNAME/charlie-work.sh"
    FIXTURES="$BATS_TEST_DIRNAME/tests"
    WORKDIR="$(mktemp -d)"
}

teardown() {
    rm -rf "$WORKDIR"
}

# --- yarn.lock (v1) ---

@test "yarn.lock v1: axios at malicious version 1.14.1 → WARN" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
axios@^1.0.0:
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

@test "yarn.lock v1: axios at malicious version 0.30.4 → WARN" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
axios@^0.30.0:
  version "0.30.4"
  resolved "https://registry.yarnpkg.com/axios/-/axios-0.30.4.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

@test "yarn.lock v1: axios at safe version → no warn, dot progress" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
axios@^1.0.0:
  version "1.7.9"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.7.9.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

@test "yarn.lock v1: no axios → no warn" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
lodash@^4.0.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

@test "yarn.lock v1: other package at 1.14.1, no axios → no false positive" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
some-package@^1.0.0:
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/some-package/-/some-package-1.14.1.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

# --- yarn.lock (berry / v2+) ---

@test "yarn.lock berry: axios at malicious version 1.14.1 → WARN" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
"axios@npm:^1.0.0":
  version: 1.14.1
  resolution: "axios@npm:1.14.1"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

@test "yarn.lock berry: other package at 1.14.1, no axios → no false positive" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
"some-package@npm:^1.0.0":
  version: 1.14.1
  resolution: "some-package@npm:1.14.1"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

# --- package-lock.json ---

@test "package-lock.json: axios at malicious version 1.14.1 → WARN" {
    cat > "$WORKDIR/package-lock.json" <<'EOF'
{
  "dependencies": {
    "axios": {
      "version": "1.14.1"
    }
  }
}
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

@test "package-lock.json: axios at safe version → no warn" {
    cat > "$WORKDIR/package-lock.json" <<'EOF'
{
  "dependencies": {
    "axios": {
      "version": "1.7.9"
    }
  }
}
EOF
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

# --- installed axios ---

@test "installed axios: malicious version in node_modules → WARN" {
    mkdir -p "$WORKDIR/node_modules/axios"
    echo '{"name":"axios","version":"1.14.1"}' > "$WORKDIR/node_modules/axios/package.json"
    touch "$WORKDIR/yarn.lock"
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

@test "installed axios: safe version in node_modules → no warn" {
    mkdir -p "$WORKDIR/node_modules/axios"
    echo '{"name":"axios","version":"1.7.9"}' > "$WORKDIR/node_modules/axios/package.json"
    touch "$WORKDIR/yarn.lock"
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

@test "installed axios: no node_modules → no warn" {
    touch "$WORKDIR/yarn.lock"
    run bash "$SCRIPT" "$WORKDIR"
    [[ "$output" != *"[WARN]"* ]]
    [[ "$output" == *"No signs of compromise."* ]]
}

@test "fixture: bad-axios-installed → WARN malicious axios installed" {
    run bash "$SCRIPT" "$FIXTURES/bad-axios-installed"
    [[ "$output" == *"[WARN] Malicious axios version"* ]]
}

# --- progress output ---

@test "progress: x printed for each warn, dot for each ok" {
    cat > "$WORKDIR/yarn.lock" <<'EOF'
axios@^1.0.0:
  version "1.14.1"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz"
EOF
    run bash "$SCRIPT" "$WORKDIR"
    # 3 checks per lockfile + 1 rat check; axios warn = x, others ok = .
    [[ "$output" == *x* ]]
    [[ "$output" == *"."* ]]
}
