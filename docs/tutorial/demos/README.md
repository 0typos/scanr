# Tutorial demos

One recording per section of [`../../tutorial.md`](../../tutorial.md), against the lab:
an [asciinema](https://asciinema.org) `.cast` and the same recording rendered to a `.gif`
by [`agg`](https://github.com/asciinema/agg), which the tutorial embeds under each
heading. Play a cast:

```console
asciinema play docs/tutorial/demos/05-socks5.cast
```

| cast | tutorial section |
|---|---|
| `00-lab` | The lab: `scanr-lab check` |
| `01-first-scan` | 1. A first scan, and the file it leaves behind (plus the same ports via nmap) |
| `02-record` | 2. Reading the record: verify, a tampered and a truncated copy, summarize, `--format nmap` / `list` |
| `03-plan` | 3. Look before you scan |
| `05-socks5` | 5. dante, then `ssh -D`: fidelity measured, then the scan |
| `06-http-connect` | 6. squid: `open_only`, honest `error`s |
| `07-chain-pool` | 7. A chain with the exit hop's fidelity; a pool with `via` on every result |
| `08-interrupt` | 8. Ctrl-C after 1.5 s, `output remainder`, piped back into `run --pairs -`, verified |
| `09-tls` | 9. Banners, `--tls`, `--tls-versions` against the old appliance |
| `10-calibrate` | 10. `transport test --calibrate` finding 3proxy's connection cap |

Section 4 has no commands; section 11 is a checklist.

## Re-recording

```console
cd docs/tutorial
./scanr-lab up && ./scanr-lab tunnel
./demos/record            # all, into demos/*.cast and demos/*.gif
./demos/record 05 08      # a subset
./demos/record --no-gif   # casts only (no agg needed)
./demos/record --render   # re-render demos/*.gif from the existing casts, no lab needed
```

Needs `asciinema` (`uv tool install asciinema`), `agg` (`cargo install --git
https://github.com/asciinema/agg`), `target/release/scanr` (`cargo build --release`) and
`jq`. `nmap` is used in `01` if present. Each command is preceded by a `# comment`
(`COMMENT_PAUSE`, 2 s), typed at `TYPE_DELAY` (40 ms/char), held `PRE_RUN` (1.5 s)
before it runs, then `POST_RUN` (2.5 s) after its output; idle gaps are capped at
`IDLE_LIMIT` (4 s); terminal is `COLS`×`ROWS` (100×32). Records go to `results*/` here, wiped before and after.
