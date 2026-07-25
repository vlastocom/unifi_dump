"""Generate a synthetic UniFi ``.unf`` site export for tests.

This builds a tiny BSON document stream in the same flat ``__cmd`` / ``collection``
shape a real controller writes, gzips it as ``db.gz`` inside a ZIP, then
AES-128-CBC encrypts that with the fixed, publicly documented UniFi backup key.
The result is a byte-for-byte *structural* twin of a real ``.unf`` — same
crypto, same container, same document layout — but with entirely fake data and
no real secrets.

It doubles as a compact reference for the ``.unf`` on-disk format, and as the
inverse of the decoder in ``unifi_dump.py`` (a minimal BSON *encoder*).

Run directly to drop a fixture on disk (handy for a manual end-to-end run)::

    python3 tests/_fake_unf.py /tmp/fake_site.unf
    python3 unifi_dump.py /tmp/fake_site.unf
"""
from __future__ import annotations

import gzip
import io
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

# The same fixed AES-128-CBC key/iv every UniFi backup uses (public knowledge).
UNIFI_KEY = "626379616e676b6d6c756f686d617273"
UNIFI_IV = "75626e74656e74657270726973656170"


class ObjectId(bytes):
    """12 raw bytes; the decoder renders these as a 24-char hex string."""


# --------------------------------------------------------------------------
# Minimal BSON encoder — the inverse of unifi_dump's decoder, only the handful
# of element types the fixtures need.
# --------------------------------------------------------------------------
def _cstr(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _element(name: str, value) -> bytes:
    if isinstance(value, ObjectId):                       # 0x07 ObjectId
        return b"\x07" + _cstr(name) + bytes(value)
    if isinstance(value, bool):                           # 0x08 boolean
        return b"\x08" + _cstr(name) + (b"\x01" if value else b"\x00")
    if isinstance(value, int):                            # 0x10 int32
        return b"\x10" + _cstr(name) + struct.pack("<i", value)
    if isinstance(value, str):                            # 0x02 string
        raw = value.encode("utf-8") + b"\x00"
        return b"\x02" + _cstr(name) + struct.pack("<i", len(raw)) + raw
    if isinstance(value, dict):                           # 0x03 embedded doc
        return b"\x03" + _cstr(name) + encode_document(value)
    if isinstance(value, list):                           # 0x04 array
        return b"\x04" + _cstr(name) + encode_document(
            {str(i): v for i, v in enumerate(value)}
        )
    if value is None:                                     # 0x0A null
        return b"\x0a" + _cstr(name)
    raise TypeError(f"unsupported fixture value type: {type(value)!r}")


def encode_document(doc: dict) -> bytes:
    body = b"".join(_element(k, v) for k, v in doc.items()) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


# --------------------------------------------------------------------------
# The fake site content. Two collections, a couple of secrets (to prove
# redaction), and a public *_fingerprint (to prove it is kept).
# --------------------------------------------------------------------------
_OID_SETTING = ObjectId(bytes.fromhex("0123456789abcdef01234567"))
_OID_USER = ObjectId(bytes.fromhex("0123456789abcdef01234568"))

FAKE_DOCS = [
    {"__cmd": "select", "collection": "setting"},
    {
        "_id": _OID_SETTING,
        "key": "mgmt",
        "x_ssh_username": "admin",
        "x_ssh_password": "s3cr3t-ssh",
        "x_ssh_hostkey_fingerprint": "aa:bb:cc:dd",
    },
    {"__cmd": "select", "collection": "user"},
    {
        "_id": _OID_USER,
        "mac": "00:11:22:33:44:55",
        "name": "example-device",
        "fixed_ip": "192.168.1.10",
        "use_fixedip": True,
        "x_password": "hunter2",
    },
]


def build_unf_bytes(docs=FAKE_DOCS) -> bytes:
    """Return the bytes of a synthetic ``.unf`` for ``docs`` (needs ``openssl``)."""
    bson = b"".join(encode_document(d) for d in docs)
    db_gz = gzip.compress(bson)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("db.gz", db_gz)
    plaintext = buf.getvalue()

    return subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-K", UNIFI_KEY, "-iv", UNIFI_IV],
        input=plaintext, stdout=subprocess.PIPE, check=True,
    ).stdout


def build_fake_unf(path, docs=FAKE_DOCS) -> Path:
    """Write a synthetic ``.unf`` to ``path`` and return it."""
    path = Path(path)
    path.write_bytes(build_unf_bytes(docs))
    return path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "fake_site.unf"
    build_fake_unf(out)
    print(f"wrote {out}")
