#!/usr/bin/env bash
# shellcheck disable=SC2086

set -ex

# https://stackoverflow.com/questions/34405047/
function create_all_branches() {
    # Keep track of where Travis put us.
    # We are on a detached head, and we need to be able to go back to it.
    local build_head
    build_head="$(git rev-parse HEAD)"

    # Fetch all the remote branches. Travis clones with `--depth`, which
    # implies `--single-branch`, so we need to overwrite remote.origin.fetch to
    # do that.
    git config --replace-all remote.origin.fetch +refs/heads/*:refs/remotes/origin/*
    git fetch
    # optionally, we can also fetch the tags
    git fetch --tags

    # create the tacking branches
    for branch in $(git branch -r|grep -v HEAD) ; do
        git checkout -qf "${branch#origin/}"
    done

    # finally, go back to where we were at the beginning
    git checkout "${build_head}"
}

printf "TRAVIS_BRANCH = %s\n" "$TRAVIS_BRANCH"
printf "TRAVIS_PULL_REQUEST = %s\n" "$TRAVIS_PULL_REQUEST"
printf "TRAVIS_PULL_REQUEST_BRANCH = %s\n" "$TRAVIS_PULL_REQUEST_BRANCH"
printf "FLAGS = %s\n" "$FLAGS"
if [[ "$TRAVIS_BRANCH" != "master" ]] && [[ "$TRAVIS_PULL_REQUEST" == "false" ]]; then
    git show --shortstat
    create_all_branches
    git show --shortstat
    git checkout master
    git merge --no-edit --no-commit "$TRAVIS_BRANCH"
    git status --short --branch
    MERGE_TEST="1"
fi
if [[ -n "$MERGE_TEST" ]]; then
    cargo build --verbose --release $FLAGS
    cargo build --verbose --release --features=notification $FLAGS
    cargo build --verbose --release --features=encryption $FLAGS
    cargo build --verbose --release --features=yubikey $FLAGS
    cargo build --verbose --release --features=all $FLAGS
    cargo test --features=all $FLAGS
fi
