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

# Check that commands exist
@check +CMDS:
	echo {{CMDS}} | xargs -n1 sh -c 'if ! command -v $1 >/dev/null 2>&1 /dev/null; then echo "$1 is required!"; exit 1; fi' bash


gen-syscall: (check "yarn" "rg" "curl" "tar")
    #!/usr/bin/env bash

    set -xe

    cd ./resources/generate_syscalls
    out_file="../../src/syscalls.json"

    k_version="6.1.16"
    k_link="https://cdn.kernel.org/pub/linux/kernel/v${k_version%%.*}.x/linux-${k_version}.tar.xz"
    k_dir="linux-${k_version}"

    syscall_table="${k_dir}/arch/x86/entry/syscalls/syscall_64.tbl"

    if [ ! -d "$k_dir" ]; then
        curl $k_link > linux-${k_version}.tar.xz
        tar xvf linux-${k_version}.tar.xz
        rm linux-${k_version}.tar.xz
    fi

    if [ ! -f ${syscall_table} ]; then
        echo "$syscall_table doesn't exist"
        exit 1
    fi

    yarn
    yarn start --output "$out_file" --linux-source "${k_dir}"
