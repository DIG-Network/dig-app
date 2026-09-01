# Running dig-app on a headless Linux server

This is the deployment shape a server operator has: no desktop session, no tray, and
`--help` as the only interface. Everything here is measured on Ubuntu Server 24.04 with
zero desktop packages (dig-app#303, #309, #310).

## 1. Install the `-headless` artifact, not the default one

Two `dig-app` binaries are published for each Linux arch:

| asset stem | links | runs on a server |
|---|---|---|
| `dig-app-<ver>-linux-<arch>` | GTK 3, GDK, cairo (`DT_NEEDED`) | **no** |
| `dig-app-<ver>-linux-<arch>-headless` | `libgcc_s`, `libc`, `ld-linux` only | yes |

The default build's GTK entries are resolved by the dynamic loader **before `main()`**, so on
a host without those libraries the process dies at **exit 127** and prints nothing of its own.
There is no runtime degrade to reach; the choice is made when you pick the file.

Confirm before installing:

```sh
ldd ./dig-app-<ver>-linux-x64-headless      # no libgtk-3.so.0 / libgdk-3.so.0 / libcairo.so.2
./dig-app-<ver>-linux-x64-headless --version
```

`diga`, the CLI, links no desktop stack in either configuration — there is only one `diga`.

## 2. The systemd unit MUST set `HOME`

**systemd does not put `HOME` in a unit's environment.** dig-app stores the user's sealed data
under the XDG data directory, which resolves as `$XDG_DATA_HOME`, or `$HOME/.local/share` when
`XDG_DATA_HOME` is unset **or empty**. With neither variable present there is nowhere to put
the data, and the agent exits rather than guessing a location — which under `Restart=` is a
crash loop.

`XDG_DATA_HOME` is an optional override. `HOME` is the one that must be set.

```ini
# /etc/systemd/system/dig-app.service
[Unit]
Description=DIG user identity agent (headless)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dig-app
# REQUIRED: systemd omits HOME from a unit's environment, and dig-app derives its data
# directory from it. Point it at the home directory of the user below.
Environment=HOME=/var/lib/dig-app
# Optional: only to place the data somewhere other than $HOME/.local/share.
#Environment=XDG_DATA_HOME=/var/lib/dig-app/data
User=dig-app
Group=dig-app
StateDirectory=dig-app
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --home-dir /var/lib/dig-app --create-home dig-app
sudo systemctl daemon-reload
sudo systemctl enable --now dig-app
systemctl status dig-app
```

## 3. When it will not start

| symptom | cause | fix |
|---|---|---|
| exit 127, `libgtk-3.so.0: cannot open shared object file` | the default (tray) artifact on a server | install the `-headless` asset |
| `the user AppData directory is not set (HOME ...)` in a restart loop | `HOME` absent from the unit | `Environment=HOME=/var/lib/dig-app` |
| `version 'GLIBC_2.x' not found` at exec | the host's glibc is below the declared floor (SPEC.md §9) | run on a distro at or above the floor |

Setting `XDG_DATA_HOME` will not fix the second row on its own if `HOME` is still absent, and
setting it to the empty string is treated as not setting it at all, per the XDG specification.
