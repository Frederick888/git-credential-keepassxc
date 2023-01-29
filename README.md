# `git-credential-keepassxc`

[![GitHub Actions Status](https://github.com/Frederick888/git-credential-keepassxc/workflows/Build%20and%20Test/badge.svg)](https://github.com/Frederick888/git-credential-keepassxc/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![crates.io version](https://img.shields.io/crates/v/git-credential-keepassxc?color=greenyellow&cacheSeconds=1800)](https://crates.io/crates/git-credential-keepassxc)

`git-credential-keepassxc` is a [Git credential](https://git-scm.com/docs/gitcredentials) helper that allows Git (and shell scripts) to get/store logins from/to [KeePassXC](https://keepassxc.org/).

It communicates with KeePassXC using [keepassxc-protocol](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md), which was originally designed for browser extensions.

## How to install

### Quick

1. Install [Rust](https://www.rust-lang.org/) compiler via [rustup](https://rustup.rs/) or your favourite package manager
0. Run `cargo install --locked git-credential-keepassxc` and it will be installed to [Cargo installation root](https://doc.rust-lang.org/cargo/commands/cargo-install.html#description)

### Pre-Built Binaries (Experimental)

Experimental pre-built binaries are available at the [GitHub release page](https://github.com/Frederick888/git-credential-keepassxc/releases).

`*-minimal` ones are built with no optional features, and `*-full` ones are built with all.

### Optional features

`git-credential-keepassxc` has the following optional features:

| Feature         | Description                                                                                                                      |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------|
| `all`           | Enable all features                                                                                                              |
| `notification`  | Desktop notifications, helpful if `git-credential-keepassxc` is used in scripts                                                  |
| `yubikey`       | Allow encrypting configuration file using YubiKey HMAC-SHA1                                                                      |
| `strict-caller` | Enforce caller limiting when there are associated databases (read the [Limiting callers](#limiting-callers) section for details) |

You can use [cargo-update](https://crates.io/crates/cargo-update) to make the features persistent across updates.

```sh
# install cargo-update first
$ cargo install --locked cargo-update
# enable and persist features
$ cargo install --locked --features <FEATURE>... git-credential-keepassxc
# note the different order of package name and --feature (singular) flag
$ cargo install-update-config git-credential-keepassxc --enforce-lock --feature <FEATURE>...

# later when you update
$ cargo install-update git-credential-keepassxc
```

## Configuration

Similar to the browser extensions, `git-credential-keepassxc` needs to be associated with KeePassXC first:

```sh
$ git-credential-keepassxc configure
$ git config --global --replace-all credential.helper 'keepassxc --git-groups'
```

A dedicated group (by default `Git`) will be created. If you want to use credentials from other groups, please check out [Filtering results](#filtering-results).

For more options, run `git-credential-keepassxc -h` to show the help message.

## Limiting callers

`git-credential-keepassxc` allows you to limit callers of the program:

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
# then add Git
$ git-credential-keepassxc caller add --uid "$(id -u)" --gid "$(id -g)" "$(command -v git)"
# you may also need to add other executables in /usr/lib/git-core/
# run `git config --global --replace-all credential.helper 'keepassxc -vv --git-groups'` to enable logs if any Git subcommand is blocked

$ sh -c 'printf "url=https://example.com\nusername=foo\n" | git-credential-keepassxc get'
May 10 12:51:56.108 ERRO /usr/bin/bash (uid=1000, gid=1000) is not allowed to call git-credential-keepassxc, Caused by: N/A
$ printf 'url=https://example.com\nusername=foo\n' | git credential fill
May 10 12:52:53.995 WARN Request get-logins failed. Error: No logins found, Error Code: 15
May 10 12:52:53.995 ERRO Request get-logins failed, Caused by: N/A, Message: Request get-logins failed

# disable this function
$ git-credential-keepassxc caller clear
```

*Note:* If you've enabled `strict-caller`, you must add caller profiles before configuring databases, otherwise you won't be able to run `git-credential-keepassxc` afterwards.

## Encrypting KeePassXC keys using YubiKey

By default the keys for authentication are stored in plaintext, which can be particularly dangerous if you've allowed clients to retrieve any credentials without confirmation.

`git-credential-keepassxc` is capable of encrypting these keys using YubiKey HMAC-SHA1 Challenge-Response. First make sure you've enabled the `yubikey` feature, then:

```sh
# encrypt using YubiKey slot 2 and a randomly generated challenge
$ git-credential-keepassxc encrypt challenge-response
```

To decrypt the keys:

```sh
$ git-credential-keepassxc decrypt
```

For more details, see: [wiki/Encryption](https://github.com/Frederick888/git-credential-keepassxc/wiki/Encryption)

## Filtering results

### By group names

`--group <GROUP>`. This option can be repeated. This is the name of the group itself. Paths are not supported.

### By dedicated Git group names

`--git-groups`. This uses the names of the groups created by `git-credential-keepassxc configure [--group <GROUP>]`.

Note if you have more than one databases, it's recommended to use the same group name, as this option filters all results using all the group names.

### By an advanced string field

1. In KeePassXC, go to Tools -> Settings -> Browser Integration -> Advanced, enable `Return advanced string fields which start with "KPH: "` (this is enabled by default)
0. Open the entry you'd like to hide
0. Go to Advanced
0. Add an additional attribute `KPH: git` (the space after colon is mandatory) of which the value is `false`

### A note on `git-credential-keepassxc store`

Since `git-credential-keepassxc store` consists of looking up existing entries and then updating or creating one, these filters can also stop it from updating certain entries.

This is *important* as Git may call `git-credential-keepassxc store` after validating a password, and it can update your login password entry rather than the API token one.

## Scripting

`git-credential-keepassxc` can also help manage credentials in shell scripts. You can send a request via standard input in the [git-credential input/output format](https://git-scm.com/docs/git-credential#IOFMT) then process the response.

Accepted fields in input (unknown fields are ignored):

- `url`
- `username`
- `password` (`store` requests only)

Responses are in the same format. Alternatively `get`, `totp`, `store`, and `generate-password` responses can also be formatted in JSON with `--json` flag; `get` and `totp` also support `--raw` flag.

For instance, to connect to a Remote Desktop service:

```sh
#!/usr/bin/env -S bash -euET -o pipefail -O inherit_errexit

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

## Troubleshooting and more

[Wiki](https://github.com/Frederick888/git-credential-keepassxc/wiki)
