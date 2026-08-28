# The tutorial lab

Everything [`../tutorial.md`](../tutorial.md) runs against, ready to start. The lab is a
single [`uv`](https://docs.astral.sh/uv/) script, no VM, no root. Plain Python threads
run the services, rootless podman the proxies, and a user-space `sshd` the tunnel.

```console
cd docs/tutorial
./scanr-lab up          # three loopback services; plus squid, tinyproxy, 3proxy, dante if podman exists
./scanr-lab tunnel      # optional: a throwaway sshd and `ssh -D 127.0.0.1:1088` for use case 5
./scanr-lab check       # what is up
scanr plan lab-audit
./scanr-lab down        # stop everything it started
```

Prefer it on your PATH? `./scanr-lab install` symlinks it into `uv tool dir --bin`, so
`scanr-lab up` works from anywhere. `scanr-lab uninstall` removes the symlink. The first
run fetches `typer` into uv's cache; every run after is instant.

| file | what |
|---|---|
| `scanr-lab` | the lab: `up` / `tunnel` / `check` / `down`, and `install` / `uninstall`; a PEP 723 uv script, state and logs in `.state/` |
| `scanr-lab.lock` | uv's lockfile for the script's one dependency (`typer`), so the environment is reproducible |
| `lab.py` | the services: 25025 greets, 28080 silent, 28443 TLS 1.2 (h2), 28444 TLS 1.0/1.1 only; standard library only, `--check` probes them. `scanr-lab up` spawns it; `tests/tutorial.rs` runs it directly |
| `scanr.toml` | the configuration every command in the tutorial uses; run them from this directory |
| `demos/` | one asciinema cast per tutorial section, and `demos/record` to re-record them against the lab |
| `proxies/` | `Containerfile` and one config each for squid `:3128`, tinyproxy `:3129`, 3proxy (HTTP `:3130`, SOCKS5 `:1081`), dante `:1082`; loopback only, rootless podman |

No podman? Use cases 1-4, 8 and 9 need only `lab.py`. Point `scanr.toml`'s transports at
any SOCKS5 or HTTP CONNECT proxy you have for the rest.

Records the tutorial writes land in `results*/` here and are git-ignored.
`tests/tutorial.rs` (`cargo test --test tutorial`) runs the same use cases against
`lab.py` and scanr's in-process proxy fixtures, and checks that every `scanr` command in
the tutorial still parses against the current CLI.
