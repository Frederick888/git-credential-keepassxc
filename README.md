# `git-credential-keepassxc`

[![GitHub Actions Status](https://github.com/Frederick888/git-credential-keepassxc/workflows/Build%20and%20Test/badge.svg)](https://github.com/Frederick888/git-credential-keepassxc/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![crates.io version](https://img.shields.io/crates/v/git-credential-keepassxc?color=greenyellow&cacheSeconds=1800)](https://crates.io/crates/git-credential-keepassxc)

`git-credential-keepassxc` is a [Git credential](https://git-scm.com/docs/gitcredentials) helper that allows Git (and shell scripts) to get/store logins from/to [KeePassXC](https://keepassxc.org/).

It communicates with KeePassXC using [keepassxc-protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md) which is originally designed for browser extensions.

## How to install

### Quick

1. Install [Rust](https://www.rust-lang.org/) compiler via [rustup](https://rustup.rs/) or your favourite package manager
0. Run `cargo install git-credential-keepassxc` (or `cargo install --git https://github.com/Frederick888/git-credential-keepassxc.git` for the latest development version)

*Note:* Make sure `$CARGO_INSTALL_ROOT` is in your search path.

### Pre-Built Binaries (Experimental)

Pre-built binaries are now available at the [GitHub release page](https://github.com/Frederick888/git-credential-keepassxc/releases).

The `*-minimal` ones are built with no features enabled, and `*-full` ones are built with all.

### Optional features

`git-credential-keepassxc` currently has got the following features that you can choose to opt in:

| Feature | Description |
| ------- | ----------- |
| `all` | Enable all features |
| `notification` | Desktop notifications, helpful if `git-credential-keepassxc` is used in scripts |
| `yubikey` | Allow encrypting configuration file using YubiKey HMAC-SHA1 |
| `strict-caller` | Enforce caller limiting when there are associated databases (read the [Limiting callers](#limiting-callers) section for details) |

It is suggested to use [cargo-update](https://crates.io/crates/cargo-update) to make the features you've enabled persistent across updates.

```sh
# install cargo-update first
$ cargo install cargo-update
# enable and persist features
$ cargo install --features <FEATURE>... git-credential-keepassxc
# note the flipped order of package name and --feature flag
$ cargo install-update-config git-credential-keepassxc --feature <FEATURE>...

# later when you update
$ cargo install-update git-credential-keepassxc
```

## Configuration

Similar to the browser extensions, `git-credential-keepassxc` needs to be associated with KeePassXC first.

Run:

```sh
$ git-credential-keepassxc configure
$ git config --global credential.helper keepassxc 
```

A group (by default `Git`) will be created to store new logins.

For more options, run `git-credential-keepassxc -h` to show the help message.

## Limiting callers

`git-credential-keepassxc` allows you to limit callers (though you should probably have a look at some [MAC](https://en.wikipedia.org/wiki/Mandatory_access_control) systems to properly achieve this), for instance:

```sh
# don't forget to add yourself first
$ git-credential-keepassxc caller me
Gonna save current caller to allowed callers list:
{
  "path": "/usr/bin/zsh",
  "uid": 1000,
  "gid": 1000,
  "canonicalize": false
}
Press Enter to continue...
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

*Note:* If you've enabled `strict-caller`, you must add caller profiles before configuring databases, otherwise you won't be able to run `git-credential-keepassxc` afterwards.

## Encrypting KeePassXC keys using YubiKey

By default the keys for authentication are stored in plaintext, which means it's possible for malware to extract the keys and request credentials from KeePassXC directly. This can be particularly dangerous if you've allowed clients to retrieve any credentials without confirmation.

`git-credential-keepassxc` is capable of encrypting KeePassXC keys using YubiKey Challenge-Response. First make sure you've enabled `yubikey` feature, then:

```sh
# encrypt using YubiKey slot 2 and a randomly generated challenge
$ git-credential-keepassxc encrypt challenge-response
```

To decrypt the keys and then disable this feature:

```sh
$ git-credential-keepassxc decrypt
```

For more details, see: [wiki/Encryption](https://github.com/Frederick888/git-credential-keepassxc/wiki/Encryption)

## Ignoring certain entries

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

## Security

See: [wiki/Security](https://github.com/Frederick888/git-credential-keepassxc/wiki/Security)
