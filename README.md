# pfBlockerNG

IP and DNS blocking for pfSense, maintained at
[andrebrait/pfBlockerNG](https://github.com/andrebrait/pfBlockerNG).

Original author: [BBcan177](https://github.com/BBcan177).

## Branches

| Branch | Channel | pfSense port |
|--------|---------|-------------|
| `main` | Stable | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel` first. Once stable, `devel` is merged into
`main` to cut a new production release.

---

## Development workflow

### Prerequisites

- A running pfSense instance accessible via SSH
- FreeBSD ports tree cloned at (e.g.) `~/git/FreeBSD-ports`
  ([pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports))
- Python 3.11+ for running tests locally

### Running the test suite locally

```sh
cd src/usr/local/pkg/pfblockerng
python3 -m pytest tests/ -v
```

### Building via the FreeBSD ports system

On a FreeBSD machine with the ports tree available:

```sh
# Stable
cd /usr/ports/net/pfSense-pkg-pfBlockerNG
make package

# Devel
cd /usr/ports/net/pfSense-pkg-pfBlockerNG-devel
make package
```

The resulting `.pkg` file is in `work/pkg/`.

---

## Installing on a pfSense instance for testing

Use the helper script to push files directly to a running pfSense box
over SSH. The script copies changed source files to the correct system
paths and restarts the relevant services.

```sh
./scripts/deploy.sh <pfsense-host> [--channel devel|stable]
```

Example:

```sh
./scripts/deploy.sh root@192.168.1.1
./scripts/deploy.sh root@192.168.1.1 --channel stable
```

The script defaults to the **devel** channel (files from this branch).
Pass `--channel stable` when deploying from the `main` branch.

See [`scripts/deploy.sh`](scripts/deploy.sh) for full options.

---

## Updating pfSense's ports repository

When a new version is ready to ship, tag the commit and push the tag:

```sh
# From devel (pre-release)
git tag v3.2.17
git push origin v3.2.17

# From main (production release)
git tag v3.2.16
git push origin v3.2.16
```

The release workflow will:
1. Run the test suite.
2. Publish a GitHub Release with a changelog.
3. Open a PR on [pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports)
   updating `GH_TAGNAME` in the corresponding port Makefile.

To update the ports tree manually instead:

```sh
# In your FreeBSD-ports clone, edit the appropriate Makefile:
# net/pfSense-pkg-pfBlockerNG/Makefile        (stable)
# net/pfSense-pkg-pfBlockerNG-devel/Makefile  (devel)

# Update GH_TAGNAME to the new tag, then bump PORTREVISION if the
# PORTVERSION is unchanged, or update PORTVERSION to match the new tag.
```
