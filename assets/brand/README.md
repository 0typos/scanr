# scanr brand

The mark follows one scanning pulse through an S-shaped proxy route. The three smaller
nodes are proxy hops between the larger endpoints. Cyan is the path, amber is the probe
in flight, and magenta is the endpoint state. The deep-ink tile keeps the mark legible
on light and dark backgrounds.

## Assets

| asset | use |
|---|---|
| `scanr-mark.png` | 512×512 master for README, social cards and project listings |
| `scanr-icon-128.png` | compact avatar, launcher or package icon |

Both files are opaque PNGs. Keep the deep-ink background intact; it is part of the mark.
Do not upscale the 512 px master.

## Palette

| name | hex | role |
|---|---|---|
| deep ink | `#071526` | background and high contrast |
| signal cyan | `#00CFE8` | routes, structure and trusted information |
| probe amber | `#FFB000` | active work and attention |
| state magenta | `#FF1688` | endpoint state and faults |

Use cyan as the dominant accent. Amber and magenta should stay small enough to read as
signals, not decoration. In text-first surfaces, prefer the mark plus the lowercase
`scanr` name instead of baking a wordmark into another image.
