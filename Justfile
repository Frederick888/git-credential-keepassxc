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
    cargo check --no-default-features
    for feature in default notification encryption yubikey all; do \
        cargo check --features=$feature; \
    done

clippy:
    cargo clippy --no-default-features -- -D warnings
    for feature in default notification encryption yubikey all; do \
        cargo clippy --features=$feature -- -D warnings; \
    done

check_fmt:
    cargo fmt -- --check

lint:
    just check
    just check_fmt
    just clippy

build:
    cargo build --no-default-features
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
            printf 'Upgrade dependencies\n\n%s\n' "$UPDATED_CRATES" | git commit -F -; \
        fi
    @printf 'Running cargo outdated\n'
    cargo outdated --features all -R

# vim: set filetype=just :
