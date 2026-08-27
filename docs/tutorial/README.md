# The tutorial lab

Everything [`../tutorial.md`](../tutorial.md) runs against, ready to start.

```console
cd docs/tutorial
./lab up          # three loopback services; plus squid, tinyproxy, 3proxy, dante if podman exists
./lab tunnel      # optional: a throwaway sshd and `ssh -D 127.0.0.1:1088` for use case 5
./lab check       # what is up
scanr plan lab-audit
./lab down
```

| file | what |
|---|---|
| `lab` | `up` / `tunnel` / `check` / `down`; state and logs in `.state/` |
| `lab.py` | the services: 25025 greets, 28080 silent, 28443 TLS 1.2 (h2); standard library only, `--check` probes them |
| `scanr.toml` | the configuration every command in the tutorial uses — run them from this directory |
| `proxies/` | `Containerfile` and one config each for squid `:3128`, tinyproxy `:3129`, 3proxy (HTTP `:3130`, SOCKS5 `:1081`), dante `:1082` — loopback only, rootless podman |

No podman? Use cases 1–4, 8 and 9 need only `lab.py`. Point `scanr.toml`'s transports at
any SOCKS5 or HTTP CONNECT proxy you have for the rest.

Records the tutorial writes land in `results*/` here and are git-ignored. `tests/tutorial.rs`
runs the same use cases automatically — `cargo test --test tutorial` — using `lab.py` and
scanr's in-process proxy fixtures, and checks that every `scanr` command in the tutorial
still parses against the current CLI.
