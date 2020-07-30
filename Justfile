test:
    if ! cargo test --features=all; then \
        rm -f /tmp/git-credential-keepassxc.test_*.json; \
        exit 1; \
    fi
