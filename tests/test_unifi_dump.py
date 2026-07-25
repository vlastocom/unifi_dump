"""Tests for unifi_dump — unit tests (pure Python) plus a self-contained,
openssl-backed end-to-end run over a synthetic ``.unf`` fixture.

Run with the standard library (no third-party packages needed)::

    python3 -m unittest discover -s tests -v

or, if you have pytest installed::

    pytest tests/ -v
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from _fake_unf import (  # noqa: E402
    FAKE_DOCS,
    build_fake_unf,
    encode_document,
)

import unifi_dump as ud  # noqa: E402  (path set up above)

HAVE_OPENSSL = shutil.which("openssl") is not None


class RedactionUnitTests(unittest.TestCase):
    def test_known_secret_names_are_sensitive(self):
        for key in [
            "x_password", "password", "psk", "x_ssh_password", "x_secret",
            "x_wireguard_private_key", "syslog_key", "utm_token",
        ]:
            self.assertTrue(ud.is_sensitive(key), key)

    def test_regex_catches_versioned_secret_fields(self):
        self.assertTrue(ud.is_sensitive("x_something_password"))
        self.assertTrue(ud.is_sensitive("x_new_secret"))
        self.assertTrue(ud.is_sensitive("x_future_hostkey"))

    def test_public_fingerprints_are_kept(self):
        self.assertFalse(ud.is_sensitive("x_ssh_hostkey_fingerprint"))
        self.assertFalse(ud.is_sensitive("x_fingerprint"))

    def test_ordinary_fields_are_kept(self):
        for key in ["mac", "name", "fixed_ip", "ip", "hostname", "_id"]:
            self.assertFalse(ud.is_sensitive(key), key)

    def test_redact_walks_nested_structures(self):
        src = {"a": {"x_password": "p"}, "b": [{"psk": "k"}], "c": "keep"}
        out = ud.redact(src)
        self.assertEqual(out["a"]["x_password"], ud.PLACEHOLDER)
        self.assertEqual(out["b"][0]["psk"], ud.PLACEHOLDER)
        self.assertEqual(out["c"], "keep")

    def test_redact_leaves_empty_secret_untouched(self):
        # Nothing to hide in an empty/None/False value.
        self.assertEqual(ud.redact({"x_password": ""})["x_password"], "")


class BsonDecodeUnitTests(unittest.TestCase):
    def test_decode_stream_matches_source_docs(self):
        blob = b"".join(encode_document(d) for d in FAKE_DOCS)
        docs = ud.decode_bson_stream(blob)
        self.assertEqual(len(docs), len(FAKE_DOCS))
        self.assertEqual(docs[0], {"__cmd": "select", "collection": "setting"})
        self.assertEqual(docs[1]["x_ssh_password"], "s3cr3t-ssh")
        # ObjectId decodes to a 24-char hex string.
        self.assertEqual(docs[1]["_id"], "0123456789abcdef01234567")
        self.assertIs(docs[3]["use_fixedip"], True)
        self.assertEqual(docs[3]["fixed_ip"], "192.168.1.10")

    def test_decode_handles_each_value_type(self):
        blob = encode_document(
            {"i": 42, "b": False, "s": "x", "n": None,
             "arr": ["a", "b"], "sub": {"k": "v"}}
        )
        (doc,) = ud.decode_bson_stream(blob)
        self.assertEqual(doc["i"], 42)
        self.assertIs(doc["b"], False)
        self.assertEqual(doc["s"], "x")
        self.assertIsNone(doc["n"])
        self.assertEqual(doc["arr"], ["a", "b"])
        self.assertEqual(doc["sub"], {"k": "v"})


@unittest.skipUnless(HAVE_OPENSSL, "openssl is required to build/decode a .unf")
class EndToEndTests(unittest.TestCase):
    """Build a synthetic .unf, then drive the CLI over it as a subprocess."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="unifi_dump_e2e_"))
        self.unf = build_fake_unf(self.tmp / "fake_site.unf")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "unifi_dump.py"), *args],
            capture_output=True, text=True, check=True,
        )

    def test_decode_to_stdout(self):
        result = self._cli(str(self.unf))
        docs = json.loads(result.stdout)
        collections = [d["collection"] for d in docs if "__cmd" in d]
        self.assertEqual(collections, ["setting", "user"])
        # A plain (non-redacted) decode still contains the secrets.
        self.assertIn("s3cr3t-ssh", result.stdout)

    def test_decode_to_file(self):
        out = self.tmp / "out.json"
        self._cli(str(self.unf), str(out))
        docs = json.loads(out.read_text())
        self.assertEqual(len(docs), len(FAKE_DOCS))

    def test_redact_end_to_end(self):
        out = self.tmp / "redacted.json"
        self._cli("--redact", str(self.unf), str(out))
        text = out.read_text()
        self.assertNotIn("s3cr3t-ssh", text)   # ssh password gone
        self.assertNotIn("hunter2", text)      # user password gone
        self.assertIn(ud.PLACEHOLDER, text)
        self.assertIn("aa:bb:cc:dd", text)     # public fingerprint kept
        self.assertIn("example-device", text)  # ordinary field kept


if __name__ == "__main__":
    unittest.main(verbosity=2)
