set shell := ["bash", "+u", "-c"]

alias cov := coverage

test:
    if ! cargo test; then \
        just test-clean; \
        exit 1; \
    fi
    if ! cargo test --features=notification,encryption,yubikey; then \
        just test-clean; \
        exit 1; \
    fi
    if ! cargo test --features=all; then \
        just test-clean; \
        exit 1; \
    fi

test-clean:
    rm -f /tmp/git-credential-keepassxc.test_*.json
    [[ -z "$TMPDIR" ]] || rm -f "$TMPDIR"/git-credential-keepassxc.test_*.json

check:
    for feature in default notification encryption yubikey all; do \
        cargo check --features=$feature; \
    done

clippy:
    for feature in default notification encryption yubikey all; do \
        cargo clippy --features=$feature --locked -- -D warnings; \
        cargo clippy --features=$feature --locked --tests -- -D warnings; \
    done

check_fmt:
    cargo fmt -- --check

lint:
    just check
    just check_fmt
    just clippy

build:
    for feature in default notification encryption yubikey all; do \
        cargo build --release --features=$feature; \
    done

build-win:
    env PKG_CONFIG_ALLOW_CROSS=1 cargo build --features=all --release --target=x86_64-pc-windows-gnu

coverage:
    env CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort" \
        RUSTDOCFLAGS="-Cpanic=abort" cargo +nightly build --features=encryption,yubikey,notification
    env CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort" \
        RUSTDOCFLAGS="-Cpanic=abort" cargo +nightly test --features=encryption,yubikey,notification
    env CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort" \
        RUSTDOCFLAGS="-Cpanic=abort" cargo +nightly build --features=all
    env CARGO_INCREMENTAL=0 RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort" \
        RUSTDOCFLAGS="-Cpanic=abort" cargo +nightly test --features=all
    just test-clean
    grcov ./target/debug/ -s . -t html --llvm --branch --ignore-not-existing -o ./target/debug/coverage/
    if command -v xdg-open 2>&1 >/dev/null; then \
        xdg-open ./target/debug/coverage/index.html; \
    elif command -v open 2>&1 >/dev/null; then \
        open ./target/debug/coverage/index.html; \
    fi

update:
    UPDATED_CRATES="$(cargo update 2>&1 | sed -n 's/^\s*Updating \(.*->.*\)/\1/p')"; \
        if [[ -z "$UPDATED_CRATES" ]]; then \
            printf 'Already up to date\n'; \
        else \
            just test || exit 1; \
            git add Cargo.lock; \
            printf 'chore: Upgrade dependencies\n\n%s\n' "$UPDATED_CRATES" | git commit -F -; \
        fi
    @printf 'Running cargo outdated\n'
    cargo outdated --features all -R

release version:
    set -e
    @if [[ "{{version}}" == v* ]]; then printf 'Must not have v-prefix\n'; exit 1; fi
    # changelog
    if [[ "{{version}}" != *"-"* ]]; then \
        last_tag="$(git tag -l --sort version:refname | grep -v -- - | tail -n1)"; \
        clog --from="$last_tag" --setversion=v{{version}} -o ./CHANGELOG.md; \
        git add ./CHANGELOG.md; \
    fi
    # lint, test, build
    sed 's/^version = ".*"$/version = "{{version}}"/' -i ./Cargo.toml
    just lint
    just test
    just build
    git add ./Cargo.toml ./Cargo.lock
    # commit and tag
    git status
    git diff --exit-code
    git commit -m 'chore: Bump version to {{version}}'
    git tag v{{version}}

# vim: set filetype=just :
