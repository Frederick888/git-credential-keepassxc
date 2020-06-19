# `git-credential-keepassxc` [![Travis CI status](https://travis-ci.org/Frederick888/git-credential-keepassxc.svg?branch=master)](https://travis-ci.org/Frederick888/git-credential-keepassxc) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![crates.io version](https://meritbadge.herokuapp.com/git-credential-keepassxc)](https://crates.io/crates/git-credential-keepassxc)

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
$ git-credential-keepassxc caller add --uid "$(id -u)" --gid "$(id -g)" "$(readlink -f "$0")"
# then allow Git to access KeePassXC when sending emails via SMTP
$ git-credential-keepassxc caller add --uid "$(id -u)" --gid "$(id -g)" "$(command -v git)"
# also add other Git executables if you want to e.g. clone via HTTPS
$ git-credential-keepassxc caller add --uid "$(id -u)" --gid "$(id -g)" /usr/lib/git-core/git-remote-http

$ sh -c 'printf "url=https://example.com\nusername=foo\n" | git-credential-keepassxc get'
May 10 12:51:56.108 ERRO You are not allowed to use this program, Caused by: N/A, Message: You are not allowed to use this program
$ printf 'url=https://example.com\nusername=foo\n' | git credential fill
May 10 12:52:53.995 WARN Request get-logins failed. Error: No logins found, Error Code: 15
May 10 12:52:53.995 ERRO Request get-logins failed, Caused by: N/A, Message: Request get-logins failed

# disable this function
$ git-credential-keepassxc caller clear
```

## Encrypt KeePassXC keys using YubiKey

By default the keys for authentication are stored in plaintext, which means it's possible for malware to extract the keys and request credentials from KeePassXC directly. This can be particularly dangerous if you've allowed clients to retrieve any credentials without confirmation.

`git-credential-keepassxc` is capable of encrypting KeePassXC keys using YubiKey Challenge-Response. To enable this feature:

```sh
# enable YubiKey feature
$ cargo install --features=yubikey git-credential-keepassxc
# additionally if you use cargo-update
$ cargo install-update-config --feature=yubikey git-credential-keepassxc
# encrypt using YubiKey slot 2 and a randomly generated challenge
$ git-credential-keepassxc encrypt challenge-response
```

To decrypt the keys and then disable this feature:

```sh
$ git-credential-keepassxc decrypt
```

## Tip

Although currently it's not possible to return entries only from the Git group, you may still want to hide specific ones from Git (for instance GitLab allows only access tokens to clone over HTTPS when 2FA is enabled, so your password may conflict with the token). This can be done by adding a magic attribute to those entries.

1. In KeePassXC, go to Tools -> Settings -> Browser Integration -> Advanced, enable `Return advanced string fields which start with "KPH: "` (this is enabled by default)
0. Open the entry you'd like to hide
0. Go to Advanced
0. Add an additional attribute `KPH: git` (the space after colon is necessary) of which the value is `false`

## Scripting

`git-credential-keepassxc` can also help manage credentials in shell scripts. For instance, to connect to a Remote Desktop service:

```sh
#!/usr/bin/env bash

trap 'notify-send "RDP Failure" "Failed to connect to Remote Desktop service"' ERR

HOST="example.com"
PORT="3389"
USERNAME="Administrator"
PASSWORD="$(printf 'url=rdp://%s:%s\nusername=%s\n' "$HOST" "$PORT" "$USERNAME" | git-credential-keepassxc get | sed -n 's/^password=//p')"

xfreerdp /v:"$HOST:$PORT" /cert-tofu /cert:ignore \
    /size:2560x1620 /smart-sizing /scale:140 /scale-desktop:140 /scale-device:140 \
    +compression /compression-level:2 +clipboard +themes +wallpaper \
    /t:Example +decorations /u:"$USERNAME" /p:"$PASSWORD"
```
