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

## Limit callers

`git-credential-keepassxc` allows you to limit callers (though you should probably have a look at some [MAC](https://en.wikipedia.org/wiki/Mandatory_access_control) systems to properly achieve this), for instance:

```sh
# don't forget to add yourself first
$ git-credential-keepassxc callers add --uid "$(id -u)" --gid "$(id -g)" "$(readlink -f "$0")"
# then allow Git
$ git-credential-keepassxc callers add --uid "$(id -u)" --gid "$(id -g)" "$(command -v git)"

$ sh -c 'printf 'url=https://etc.com\nusername=hello\n' | git-credential-keepassxc get'
May 10 12:51:56.108 ERRO You are not allowed to use this program, Caused by: N/A, Message: You are not allowed to use this program
$ printf 'url=https://example.com\nusername=foo\n' | git credential fill
May 10 12:52:53.995 WARN Request get-logins failed. Error: No logins found, Error Code: 15
May 10 12:52:53.995 ERRO Request get-logins failed, Caused by: N/A, Message: Request get-logins failed

# disable this function
$ git-credential-keepassxc callers clear
```
