badge-crates := "[![crate](https://img.shields.io/crates/v/ftrace)](https://crates.io/crates/ftrace)"
badge-docs := "[![documentation](https://docs.rs/ftrace/badge.svg)](https://docs.rs/ftrace)"

readme:
    printf "%s\n%s\n%s" "{{ badge-crates }}" "{{ badge-docs }}" "$(cargo readme)" > README.md

# Bumps the crate,a creates a tag and commits the changed files
# Requires https://github.com/wraithan/cargo-bump
bump +TYPE:
    #!/usr/bin/env bash
    if [ ! -z "$(git status --porcelain)" ]; then
        echo "It seems there are uncommitted changes, please run this command in a clean git state"
        exit 1
    fi

    last_tag=$(git describe --tags | grep -oEm 1 '([0-9]+\.[0-9]+\.[0-9]+)')
    commits=$(git log --no-decorate --oneline "$last_tag"..HEAD | sed 's/^/- /')

    cargo fmt
    cargo bump {{ TYPE }}
    cargo check

    just readme

    version=$(grep -oEm 1 '([0-9]+\.[0-9]+\.[0-9]+)' Cargo.toml)
    printf '# %s\n\n%s\n\n%s' "$version" "$commits" "$(cat CHANGELOG.md)" > CHANGELOG.md

    git add .
    git commit -v -m "$version"
    git tag "$version"

gen-syscall:
    #!/usr/bin/env bash

    cd ./resources/generate-syscalls
    podman build -t syscall-gen .
    podman run -ti --rm syscall-gen | head -n 40