# Vendored russh patch

`vendor/russh` is [Eugeny/russh](https://github.com/Eugeny/russh) at tag
`v0.64.1`, commit `e5d80a07dc554480b6ea3b2e14adfc190407b627` (2026-10-05; the
same commit the crates.io `russh 0.64.1` package records in
`.cargo_vcs_info.json`), plus `russh-session-bind.patch`, which is wired in
through `[patch.crates-io]` in the root `Cargo.toml`. `bench.sh` and
`rust-toolchain.toml` are left out of the vendored tree; everything else is
upstream byte for byte.

## What the patch does

OpenSSH's `session-bind@openssh.com` agent extension needs three things the
client learns during key exchange and that russh previously discarded:

1. the server host key blob exactly as sent in the KEX reply,
2. the session identifier (the first exchange hash), and
3. the server's signature over that hash.

The patch keeps the raw host key and signature blobs through the client KEX
state machine, carries them in `KexProgress::Done`, and adds one method to
`russh::client::Handler`:

```rust
fn kex_binding(
    &mut self,
    server_host_key_blob: &[u8],
    session_id: &[u8],
    server_signature: &[u8],
    session: &mut Session,
) -> impl Future<Output = Result<(), Self::Error>> + Send;
```

It is called once, on the initial exchange, after `check_server_key` has
accepted the host key and before any authentication happens. The default
implementation does nothing, so existing handlers are unaffected. Server-side
code sets the new fields to `None`.

With that material an agent connection can be bound before signing, which is
what lets destination-constrained keys (`ssh-add -h user@host`) work; without
the binding OpenSSH's agent refuses to sign with such keys at all.

## Re-applying on a newer russh

The patch is a `git diff` against the pristine upstream tree, so it applies
with `patch -p1` (or `git apply`) from inside `vendor/russh`:

```sh
tag=v0.64.1   # the new release
git clone --depth 1 --branch "$tag" https://github.com/Eugeny/russh /tmp/russh
rsync -a --delete --exclude .git --exclude bench.sh --exclude rust-toolchain.toml \
    /tmp/russh/ vendor/russh/
patch -p1 -d vendor/russh < patches/russh-session-bind.patch
```

If hunks no longer apply, make the equivalent edits in `vendor/russh`, then
regenerate the patch against the pristine clone:

```sh
rsync -a --exclude .git --exclude bench.sh --exclude rust-toolchain.toml \
    --exclude Cargo.lock --exclude target vendor/russh/ /tmp/russh/
git -C /tmp/russh -c diff.noprefix=false -c diff.mnemonicPrefix=false \
    diff --no-color --no-ext-diff > patches/russh-session-bind.patch
```

Then update the tag, commit and date at the top of this file, run
`cargo test` and `tests/e2e.sh` (the constrained-key checks there fail if the
binding hook is not called), and `cargo test -p russh --lib` from
`vendor/russh` for upstream's own suite.
