#!/usr/bin/env python3
"""unifi_dump.py — decode a UniFi Network site export (.unf) to JSON.

A UniFi "Export Site" backup (.unf) is AES-128-CBC encrypted with a fixed,
publicly-documented key. Inside sits a ZIP that holds a gzipped BSON dump of
the site's MongoDB collections. This tool walks that whole pipeline in pure
Python and prints the collections as one flat JSON document stream:

    .unf  --openssl-->  ZIP  -->  db.gz  --gunzip-->  BSON  -->  JSON

It needs only `openssl` on your PATH — no mongo-tools, `bsondump`, or `pymongo`.

The decoded stream is a flat list of documents. Each collection is introduced
by a marker document of the form:

    {"__cmd": "select", "collection": "<name>"}

followed by that collection's records, then the next marker, and so on.

Optionally, `--redact` replaces secret fields (admin password, PSKs, private
keys, RADIUS/API secrets, SSH host keys, …) with "<REDACTED>" so a decoded
dump can be shared safely. Public-fingerprint fields (`*_fingerprint`) are kept.

Input is auto-detected by extension:
    <file>.unf     encrypted UniFi site export — decoded here.
    <file>.json    an already-decoded JSON document stream (`--redact` only).

Usage:
    unifi_dump.py backup.unf                    # decode to stdout
    unifi_dump.py backup.unf site.json          # decode to a file
    unifi_dump.py --redact backup.unf site.json # decode + strip secrets

SECURITY: a decoded .unf (and the .unf itself) contains the controller admin
password, VPN/RADIUS/IPSec secrets and SSH host keys in CLEARTEXT. Keep the raw
file and any non-redacted output out of version control and off shared storage.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------
# Redaction (optional, --redact): allowlist + regex, keeps *_fingerprint.
# --------------------------------------------------------------------------
SENSITIVE_NAMES = {
    "x_password", "password", "x_authkey", "x_mgmt_key", "x_api_token",
    "x_token", "utm_token",
    "x_ssh_username", "x_ssh_password", "x_ssh_sha512passwd", "x_ssh_hostkey",
    "x_passphrase", "x_iapp_key", "x_mesh_psk", "x_element_psk", "x_vwirekey",
    "psk",
    "x_wireguard_private_key", "x_ipsec_pre_shared_key", "x_secret",
    "server_certificate_key", "x_pregenerated_dh_key",
    "syslog_key",
}
SENSITIVE_RE = re.compile(
    r"^x_.*(password|passphrase|secret|psk|token|wirekey|hostkey)(?<!_fingerprint)$",
    re.IGNORECASE,
)
PLACEHOLDER = "<REDACTED>"


def is_sensitive(key: str) -> bool:
    if key.lower() in SENSITIVE_NAMES:
        return True
    if SENSITIVE_RE.match(key):
        if key.lower().endswith("_fingerprint"):
            return False
        return True
    return False


def redact(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_sensitive(k) and v not in (None, "", False):
                out[k] = PLACEHOLDER
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


# --------------------------------------------------------------------------
# Pure-Python BSON decoder. Values render as:
#   ObjectId       -> 24-char hex string
#   binary         -> {str(index): byte_int}
#   datetime/int   -> plain int
#   embedded doc   -> dict
#   array          -> list
# --------------------------------------------------------------------------
def _cstring(buf, i):
    j = buf.index(0, i)
    return buf[i:j].decode("utf-8", "surrogatepass"), j + 1


def _read_value(buf, i, t):
    if t == 0x01:  # double
        (v,) = struct.unpack_from("<d", buf, i)
        return v, i + 8
    if t in (0x02, 0x0D, 0x0E):  # string / javascript / symbol
        (ln,) = struct.unpack_from("<i", buf, i)
        i += 4
        return buf[i:i + ln - 1].decode("utf-8", "surrogatepass"), i + ln
    if t == 0x03:  # embedded document
        return _read_document(buf, i)
    if t == 0x04:  # array (document with numeric keys)
        d, i = _read_document(buf, i)
        return list(d.values()), i
    if t == 0x05:  # binary -> {index: byte}
        (ln,) = struct.unpack_from("<i", buf, i)
        i += 4
        i += 1  # subtype byte
        data = buf[i:i + ln]
        return {str(k): b for k, b in enumerate(data)}, i + ln
    if t == 0x07:  # ObjectId -> hex string
        return buf[i:i + 12].hex(), i + 12
    if t == 0x08:  # boolean
        return bool(buf[i]), i + 1
    if t == 0x09:  # UTC datetime (int64 ms) -> plain int
        (v,) = struct.unpack_from("<q", buf, i)
        return v, i + 8
    if t == 0x0A:  # null
        return None, i
    if t == 0x0B:  # regex
        p, i = _cstring(buf, i)
        o, i = _cstring(buf, i)
        return {"$regex": p, "$options": o}, i
    if t == 0x10:  # int32
        (v,) = struct.unpack_from("<i", buf, i)
        return v, i + 4
    if t == 0x11:  # timestamp (uint64)
        (v,) = struct.unpack_from("<Q", buf, i)
        return v, i + 8
    if t == 0x12:  # int64
        (v,) = struct.unpack_from("<q", buf, i)
        return v, i + 8
    if t == 0x06:  # undefined (deprecated)
        return None, i
    if t == 0xFF:  # min key
        return {"$minKey": 1}, i
    if t == 0x7F:  # max key
        return {"$maxKey": 1}, i
    raise ValueError(f"unsupported BSON element type 0x{t:02x} at offset {i}")


def _read_document(buf, i):
    (length,) = struct.unpack_from("<i", buf, i)
    end = i + length
    i += 4
    out = {}
    while i < end - 1:
        t = buf[i]
        i += 1
        name, i = _cstring(buf, i)
        val, i = _read_value(buf, i, t)
        out[name] = val
    return out, end  # `end - 1` is the trailing document terminator (0x00)


def decode_bson_stream(buf):
    docs = []
    i, n = 0, len(buf)
    while i < n:
        if n - i < 5:
            break
        d, i = _read_document(buf, i)
        docs.append(d)
    return docs


# --------------------------------------------------------------------------
# .unf unpack: openssl decrypt -> inner zip -> db.gz -> gunzip -> BSON.
# --------------------------------------------------------------------------
# Fixed AES-128-CBC key/iv used by every UniFi backup (publicly documented).
UNIFI_KEY = "626379616e676b6d6c756f686d617273"
UNIFI_IV = "75626e74656e74657270726973656170"


def unf_to_docs(unf_path: str):
    with tempfile.TemporaryDirectory() as td:
        dec = os.path.join(td, "decrypted.zip")
        subprocess.run(
            ["openssl", "enc", "-d", "-in", unf_path, "-out", dec,
             "-aes-128-cbc", "-K", UNIFI_KEY, "-iv", UNIFI_IV, "-nopad"],
            check=True,
        )
        try:  # the decrypted zip is usually readable directly
            with zipfile.ZipFile(dec) as z:
                db_gz = z.read("db.gz")
        except zipfile.BadZipFile:  # fall back to `zip -FF` repair
            fixed = os.path.join(td, "fixed.zip")
            subprocess.run(
                f"yes | zip -FF {shlex.quote(dec)} --out {shlex.quote(fixed)}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            with zipfile.ZipFile(fixed) as z:
                db_gz = z.read("db.gz")
        return decode_bson_stream(gzip.decompress(db_gz))


def load_docs(src: Path):
    if src.suffix.lower() == ".unf":
        return unf_to_docs(str(src))
    return json.loads(src.read_text())


def _redaction_report(data) -> None:
    counts: dict[str, int] = {}

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if is_sensitive(k):
                    counts[k] = counts.get(k, 0) + 1
                walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    walk(data)
    print(f"Redacted {sum(counts.values())} field occurrences "
          f"across {len(counts)} names:", file=sys.stderr)
    for k in sorted(counts):
        print(f"  {k:<28}  {counts[k]}", file=sys.stderr)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Decode a UniFi Network site export (.unf) to JSON.",
    )
    ap.add_argument("input", help="a .unf site export, or an already-decoded .json")
    ap.add_argument("output", nargs="?",
                    help="output JSON file (default: stdout)")
    ap.add_argument("--redact", action="store_true",
                    help="replace secret fields with \"<REDACTED>\"")
    args = ap.parse_args(argv)

    src = Path(args.input)
    data = load_docs(src)
    out = redact(data) if args.redact else data
    text = json.dumps(out, indent=2, sort_keys=False, ensure_ascii=False) + "\n"

    if args.output:
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)

    n_docs = len(data) if isinstance(data, list) else "n/a"
    print(f"Input: {src.name}  ->  {n_docs} top-level docs", file=sys.stderr)
    if args.redact:
        _redaction_report(data)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # A downstream reader (e.g. `head`) closed the pipe early; exit quietly
        # without the interpreter's noisy flush-time traceback.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
