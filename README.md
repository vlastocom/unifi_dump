# unifi_dump

[![CI](https://github.com/vlastocom/unifi_dump/actions/workflows/ci.yml/badge.svg)](https://github.com/vlastocom/unifi_dump/actions/workflows/ci.yml)

Decode a **UniFi Network site export** (`.unf`) into readable **JSON** — in pure
Python, using only `openssl`. No `mongo-tools`, no `bsondump`, no `pymongo`, and
no third-party Python packages.

A `.unf` "Export Site" file is AES-128-CBC encrypted with a fixed, publicly
documented key. Inside is a ZIP holding a gzipped BSON dump of the site's
MongoDB collections. `unifi_dump` walks that whole chain and prints the
collections as one flat JSON document stream:

```
.unf  ──openssl──▶  ZIP  ──▶  db.gz  ──gunzip──▶  BSON  ──▶  JSON
```

Optionally it can **redact** secrets so a decoded dump is safe to share.

## Requirements

- **Python 3.8+** (standard library only)
- **`openssl`** on your `PATH` — decrypts the `.unf`
- **`zip`** (Info-ZIP) — *optional*, used only as a fallback to repair the inner
  archive if Python's `zipfile` can't read it directly

There are no PyPI dependencies, so there is nothing to `pip install`.

## Install

It's a single self-contained script — clone the repo (or just copy the file):

```bash
git clone <your-repo-url> unifi_dump
cd unifi_dump
python3 unifi_dump.py --help
```

## Usage

```bash
# Decode a .unf to stdout
python3 unifi_dump.py backup.unf

# Decode to a file
python3 unifi_dump.py backup.unf site.json

# Decode AND strip secrets (safe to share)
python3 unifi_dump.py --redact backup.unf site.json

# Pipe into jq
python3 unifi_dump.py backup.unf | jq '.[] | select(.__cmd) | .collection'
```

Input is auto-detected by extension:

| Input       | Behaviour                                                        |
|-------------|-----------------------------------------------------------------|
| `*.unf`     | Encrypted site export — decrypted, unpacked and decoded to JSON. |
| `*.json`    | An already-decoded stream — passed through (use with `--redact`).|

Progress and the redaction summary are written to **stderr**, so piping the JSON
on **stdout** stays clean.

## Producing the `.unf` from UniFi

The `.unf` comes from the UniFi Network application's **Site Export** feature:

1. Open **Settings → System**, and find the **Site Management** section.
2. Click **Export Site**.
3. Choose what to include and proceed to the export screen.
4. Click **Download the Site Export File** to save the `.unf` locally.
5. **Do _not_ click _Continue_.**

> ⚠️ **Why "Continue" matters.** *Export Site* is really the first step of a site
> **migration** wizard. **Continue** advances that wizard — it next asks for a
> destination controller to transfer your devices to. You only want the file:
> take the **Download the Site Export File** link and then close/cancel the
> wizard. Downloading does not change anything on your controller.

(Exact label wording can vary slightly between UniFi Network versions; the key
point is: **download the file, don't proceed through the migration steps.**)

## Output format

The result is a JSON **array** of documents. Each collection is introduced by a
marker document, followed by that collection's records:

```json
[
  { "__cmd": "select", "collection": "setting" },
  { "_id": "…", "key": "mgmt", "x_ssh_username": "…" },
  { "__cmd": "select", "collection": "user" },
  { "_id": "…", "mac": "…", "name": "…" }
]
```

Value rendering:

| BSON type      | JSON rendering                          |
|----------------|-----------------------------------------|
| ObjectId       | 24-character hex string                 |
| binary         | `{ "0": 1, "1": 2, … }` (index → byte)  |
| UTC datetime   | integer (epoch milliseconds)            |
| embedded doc   | object                                  |
| array          | array                                   |

## Redaction (`--redact`)

With `--redact`, fields holding credentials or key material are replaced with
`"<REDACTED>"`:

- **Passwords / tokens** — `x_password`, `password`, `x_api_token`, `utm_token`, …
- **PSKs / shared secrets** — `psk`, `x_ipsec_pre_shared_key`, `x_mesh_psk`,
  `x_element_psk`, `x_vwirekey`, `x_secret`, `x_iapp_key`
- **Private-key material** — `x_ssh_hostkey`, `x_wireguard_private_key`,
  `server_certificate_key`, `x_pregenerated_dh_key`
- **Other** — `x_ssh_username`/`x_ssh_password`/`x_ssh_sha512passwd`,
  `x_authkey`, `x_mgmt_key`, `x_passphrase`, `syslog_key`

Any field matching `x_*(password|passphrase|secret|psk|token|wirekey|hostkey)`
is also caught, so version-specific new fields are redacted by default.
**Public** `*_fingerprint` fields are intentionally kept.

If you find a secret field this list misses, add it to `SENSITIVE_NAMES` near the
top of `unifi_dump.py` — over-redaction is preferable to under-redaction.

## ⚠️ Security

A `.unf` — and any **non**-redacted JSON decoded from it — contains, in
**cleartext**: the controller admin password, VPN / RADIUS / IPSec secrets,
WireGuard private keys, and SSH host keys. Treat both like a password file:

- Never commit a raw `.unf` or a non-redacted dump to a repository.
- Only share output produced with `--redact`, and eyeball it first.

## How it works

`openssl enc -d -aes-128-cbc` with the fixed key/IV decrypts the `.unf` to a ZIP.
The ZIP's `db.gz` entry is a gzipped BSON stream. The script gunzips it and
decodes the BSON with a small dependency-free reader, emitting the same flat
`__cmd`/`collection` document stream the controller wrote — as JSON.

## Development

The utility itself has no runtime dependencies. The only dev tools are `ruff`
(lint) and, optionally, `pytest` — both listed in `requirements-dev.txt`.

### Layout

```
unifi_dump.py            the tool
tests/
  test_unifi_dump.py     unit tests + end-to-end tests
  _fake_unf.py           synthetic .unf generator (a minimal BSON *encoder*)
pyproject.toml           ruff configuration
```

### Running the tests

Tests use the standard-library `unittest`, so they run with nothing installed:

```bash
python3 -m unittest discover -s tests -v
# or, if you have it:  pytest tests/ -v
```

Three groups:

- **redaction** — `is_sensitive` / `redact`, including that `*_fingerprint`
  fields are kept;
- **BSON decode** — round-trips each value type through the decoder;
- **end-to-end** — builds a synthetic `.unf` and drives the CLI over it as a
  subprocess (auto-skipped if `openssl` isn't on `PATH`).

### The synthetic `.unf` fixture

The end-to-end tests never need a real backup (those hold real secrets).
`tests/_fake_unf.py` instead builds a **structural twin**: it encodes a couple
of fake documents to BSON, gzips them as `db.gz` inside a ZIP, and AES-128-CBC
encrypts that with the same fixed key a real controller uses. That drives the
full `openssl → unzip → gunzip → BSON → JSON` pipeline against known data.

Generate one on disk for a manual end-to-end run:

```bash
python3 tests/_fake_unf.py /tmp/fake_site.unf
python3 unifi_dump.py /tmp/fake_site.unf             # decode
python3 unifi_dump.py --redact /tmp/fake_site.unf    # decode + redact
```

### Linting

```bash
pip install ruff        # or: python3 -m venv .venv && .venv/bin/pip install ruff
ruff check .
```

Config lives in `pyproject.toml` (`[tool.ruff]`): pycodestyle + pyflakes +
isort + pyupgrade + bugbear, 99-column lines.

## License

[MIT](LICENSE) © 2026 Vlastimil Chvojka

