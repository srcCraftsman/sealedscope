# sealedscope

A terminal UI for inspecting [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) in Kubernetes clusters.

```
┌ Sealing Keys ──────┐┌ Sealed Secrets ───────────────────────────────────┐
│ key-abc2f  active  ││ NAME                  NAMESPACE   AGE              │
│ key-d91e   expired ││ my-app-db-password    production  3d               │
│ [unknown]          ││ api-credentials       staging     12h              │
└────────────────────┘└───────────────────────────────────────────────────┘
┌ Detail ────────────────────────────────────────────────────────────────── ┐
│ name: my-app-db-password                                                  │
│ namespace: production                                                     │
│ sealed-by: key-abc2f                                                      │
│ created: 2026-05-25T10:30:00Z                                             │
└───────────────────────────────────────────────────────────────────────────┘
```

## What it does

`sealedscope` live-watches a cluster's sealing keys and `SealedSecret` resources and groups each secret under the key that sealed it. It resolves key attribution in two ways:

1. **Annotation match** — reads the `sealedsecrets.bitnami.com/sealed-by` annotation set by the controller.
2. **Timestamp fallback** — for older secrets without the annotation, picks the most-recently-created key whose creation time is ≤ the secret's creation time.

Secrets that can't be attributed land in the `[unknown]` bucket.

## Prerequisites

- Rust toolchain (edition 2024 / Rust 1.85+)
- A kubeconfig with access to the target cluster
- The sealed-secrets controller must be running in the cluster

## Installation

```sh
git clone https://github.com/yourname/sealedscope
cd sealedscope
cargo install --path .
```

Or build without installing:

```sh
cargo build --release
./target/release/sealedscope
```

## Usage

```
sealedscope [OPTIONS]

Options:
      --controller-namespace <NS>   Namespace where the sealed-secrets controller runs
                                    [default: sealed-secrets]
      --context <CONTEXT>           Kubeconfig context to start with
                                    [default: current-context from kubeconfig]
  -h, --help                        Print help
  -V, --version                     Print version
```

### Examples

```sh
# Use the active kubeconfig context, controller in default namespace
sealedscope

# Override the controller namespace
sealedscope --controller-namespace kube-system

# Start watching a specific context
sealedscope --context my-prod-cluster
```

## Key bindings

| Key | Action |
|-----|--------|
| `↑` / `k` | Navigate up |
| `↓` / `j` | Navigate down |
| `Tab` | Cycle focus: Keys → Secrets → Detail |
| `c` | Open context switcher (switch kubeconfig context) |
| `r` | Force re-fetch (restart watchers) |
| `n` | Toggle namespace filter (all namespaces / default namespace only) |
| `q` / `Ctrl+C` | Quit |
| `?` | Show help overlay |

## UI layout

The screen is split into three panes:

- **Keys** (left) — lists all sealing keys found in the controller namespace, each marked `active` or `expired`. Select a key to filter the secrets pane.
- **Secrets** (top-right) — sealed secrets that belong to the selected key, showing name, namespace, and age.
- **Detail** (bottom-right) — full metadata for the selected secret (labels, annotations, creation timestamp).

Focus cycles through the three panes with `Tab`. Navigation keys (`↑/↓`, `j/k`) apply to the focused pane; in the Detail pane they scroll the content.

## Development

```sh
cargo test       # run unit tests
cargo clippy     # lint
cargo build      # debug build
```
