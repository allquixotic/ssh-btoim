# Vendored russh patch

`vendor/russh` is [Eugeny/russh](https://github.com/Eugeny/russh) at commit
`d49f3e7a4d674beeeac7fdd1f0e7b49352bef488` (v0.63.3, 2026-09-13) plus
`russh-session-bind.patch`, which is wired in through `[patch.crates-io]` in
the root `Cargo.toml`.

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

```sh
git clone --depth 1 https://github.com/Eugeny/russh /tmp/russh
rsync -a --exclude .git --exclude bench.sh --exclude rust-toolchain.toml /tmp/russh/ vendor/russh/
patch -p1 -d vendor/russh < patches/russh-session-bind.patch
```

Regenerate the patch after edits with:

```sh
diff -ru -x .git -x bench.sh -x rust-toolchain.toml /tmp/russh vendor/russh > patches/russh-session-bind.patch
```
