# `git-credential-keepassxc`

`git-credential-keepassxc` is a [Git credential](https://git-scm.com/docs/gitcredentials) helper that allows Git to get/store logins from/to [KeePassXC](https://keepassxc.org/).

It communicates with KeePassXC using [keepassxc-protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md) which is originally designed for browser extensions.

## How to install

1. Install [Rust](https://www.rust-lang.org/) compiler via [rustup](https://rustup.rs/) or your favourite package manager
0. Run `cargo install git-credential-keepassxc` (or `cargo install --git https://github.com/Frederick888/git-credential-keepassxc.git` for the latest development version)

*Note:* Make sure `$CARGO_INSTALL_ROOT` is in your search path.

## Configuration

Similar as the browser extensions, `git-credential-keepassxc` needs to be associated with KeePassXC first.

Run:

```sh
$ git-credential-keepassxc configure
$ git config --global credential.helper keepassxc 
```

A group (by default `Git`) will be created to store new logins.
