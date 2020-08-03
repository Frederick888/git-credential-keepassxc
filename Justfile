test:
    if ! cargo test --features=all; then \
        rm -f /tmp/git-credential-keepassxc.test_*.json; \
        [[ -n "$TMPDIR" ]] && rm -f "$TMPDIR"/git-credential-keepassxc.test_*.json; \
        exit 1; \
    fi

check:
    for feature in default notification encryption yubikey all; do \
        cargo check --features=$feature; \
    done

build:
    for feature in default notification encryption yubikey all; do \
        cargo build --release --features=$feature; \
    done
