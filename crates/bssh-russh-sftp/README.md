# bssh-russh-sftp

Temporary fork of [russh-sftp](https://crates.io/crates/russh-sftp) with a `serde_bytes` performance fix for SFTP `Write` and `Data` packets.

This crate exists so bssh can ship the packet serialization fix independently while keeping the public crate name usable through Cargo's `package = "bssh-russh-sftp"` dependency alias.

## The Problem

`russh-sftp` 2.1.1 derives serde for `Vec<u8>` fields in `SSH_FXP_WRITE` and `SSH_FXP_DATA`. With the crate's custom deserializer, that routes through `deserialize_seq` and reads payload bytes one at a time. Large transfers spend substantial CPU in serde's generic `VecVisitor` path.

## The Fix

The fork annotates the binary payload fields with `#[serde(with = "serde_bytes")]` and implements compatible `serialize_bytes` framing in the SFTP serializer. The wire format remains `u32 length + bytes`, but deserialization uses the existing bulk byte-buffer path.

## Sync with Upstream

```bash
cd crates/bssh-russh-sftp
./sync-upstream.sh 2.1.1
```

Local changes are kept as patch files under `patches/`.

## License

Apache-2.0 (same as russh-sftp)
