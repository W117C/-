"""Tests for OOB callback infrastructure.

Covers CallbackStore (persistent JSONL), CallbackServer (HTTP server),
and callback URL generation.
"""

from __future__ import annotations

import json
import threading
import time
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from secagent.oob import (
    CallbackRecord,
    CallbackStore,
    CallbackServer,
    generate_callback_id,
    create_callback_url,
)


class TestCallbackRecord:
    def test_to_dict_roundtrip(self):
        rec = CallbackRecord(
            callback_id="abc123",
            source_ip="10.0.0.1",
            method="GET",
            path="/abc123/secret",
            headers={"User-Agent": "curl"},
            body="",
        )
        d = rec.to_dict()
        assert d["callback_id"] == "abc123"
        assert d["source_ip"] == "10.0.0.1"

    def test_from_dict(self):
        d = {
            "callback_id": "xyz789",
            "source_ip": "192.168.1.1",
            "method": "POST",
            "path": "/xyz789",
            "headers": {"Content-Type": "application/json"},
            "body": '{"test": true}',
            "timestamp": "2026-07-09T10:00:00+00:00",
        }
        rec = CallbackRecord.from_dict(d)
        assert rec.callback_id == "xyz789"
        assert rec.method == "POST"
        assert rec.source_ip == "192.168.1.1"


class TestCallbackStore:
    def test_add_and_get(self, tmp_path):
        store = CallbackStore(str(tmp_path / "test.jsonl"))
        rec = CallbackRecord(
            callback_id="test1", source_ip="10.0.0.1",
            method="GET", path="/test1", headers={},
        )
        store.add(rec)
        records = store.get("test1")
        assert len(records) == 1
        assert records[0].source_ip == "10.0.0.1"

    def test_has_callback_true(self, tmp_path):
        store = CallbackStore(str(tmp_path / "test.jsonl"))
        store.add(CallbackRecord(
            callback_id="c1", source_ip="10.0.0.1",
            method="GET", path="/c1", headers={},
        ))
        assert store.has_callback("c1") is True

    def test_has_callback_false(self, tmp_path):
        store = CallbackStore(str(tmp_path / "test.jsonl"))
        assert store.has_callback("nonexistent") is False

    def test_multiple_callbacks_same_id(self, tmp_path):
        store = CallbackStore(str(tmp_path / "test.jsonl"))
        for i in range(3):
            store.add(CallbackRecord(
                callback_id="multi", source_ip=f"10.0.0.{i}",
                method="GET", path="/multi", headers={},
            ))
        records = store.get("multi")
        assert len(records) == 3

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "persist.jsonl")
        store1 = CallbackStore(path)
        store1.add(CallbackRecord(
            callback_id="persist", source_ip="10.0.0.1",
            method="GET", path="/persist", headers={},
        ))
        # Create new instance reading from same file
        store2 = CallbackStore(path)
        assert store2.has_callback("persist")
        records = store2.get("persist")
        assert len(records) == 1

    def test_cleanup_removes_old_records(self, tmp_path):
        path = str(tmp_path / "cleanup.jsonl")
        store = CallbackStore(path)
        # Add a record with old timestamp
        old_rec = CallbackRecord(
            callback_id="old", source_ip="10.0.0.1",
            method="GET", path="/old", headers={},
            timestamp=__import__("datetime").datetime(
                2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
            ),
        )
        store.add(old_rec)
        # Add a recent record
        store.add(CallbackRecord(
            callback_id="new", source_ip="10.0.0.1",
            method="GET", path="/new", headers={},
        ))
        removed = store.cleanup(max_age_seconds=3600)
        assert removed == 1
        assert store.has_callback("old") is False
        assert store.has_callback("new") is True

    def test_thread_safe(self, tmp_path):
        """Simulate concurrent writes."""
        store = CallbackStore(str(tmp_path / "thread.jsonl"))
        errors = []

        def writer(cid: str):
            try:
                for _ in range(10):
                    store.add(CallbackRecord(
                        callback_id=cid, source_ip="10.0.0.1",
                        method="GET", path=f"/{cid}", headers={},
                    ))
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer, args=("t1",))
        t2 = threading.Thread(target=writer, args=("t2",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0
        assert len(store.get("t1")) == 10
        assert len(store.get("t2")) == 10


class TestCallbackServer:
    def test_start_and_stop(self, tmp_path):
        server = CallbackServer(port=0, store_path=str(tmp_path / "oob.jsonl"))
        server.start()
        assert server._server is not None
        assert server._thread is not None
        server.stop()
        assert server._server is None

    def test_get_url(self, tmp_path):
        server = CallbackServer(port=8080, store_path=str(tmp_path / "oob.jsonl"))
        url = server.get_url("abc123", public_host="example.com")
        assert url == "http://example.com:8080/abc123"

    def test_server_receives_callback(self, tmp_path):
        """Start server, send HTTP request to it, verify callback recorded."""
        import http.client
        # Use a random available port
        cid = f"testcallback_{generate_callback_id()}"
        server = CallbackServer(port=0, store_path=str(tmp_path / "oob.jsonl"))
        server.start()
        try:
            # Get the actual port assigned (port=0 → OS assigns)
            port = server._server.server_address[1]
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", f"{cid}/path")
            resp = conn.getresponse()
            assert resp.status == 200
            conn.close()

            # Give handler a moment to write
            time.sleep(0.2)
            assert server.has_callback(cid)
            records = server.get(cid)
            assert len(records) == 1
            assert records[0].method == "GET"
            assert records[0].path == f"{cid}/path"
        finally:
            server.stop()

    def test_poll_timeout(self, tmp_path):
        """poll() with timeout should return empty if no callback arrives."""
        server = CallbackServer(port=0, store_path=str(tmp_path / "oob.jsonl"))
        server.start()
        try:
            records = server.poll("nevercome", timeout=0.5)
            assert records == []
        finally:
            server.stop()


class TestCallbackURLGeneration:
    def test_generate_callback_id_unique(self):
        ids = {generate_callback_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generate_callback_id_format(self):
        cid = generate_callback_id()
        assert len(cid) == 12
        assert cid.isalnum()

    def test_create_callback_url(self):
        url = create_callback_url("https://callback.example.com", "abc123")
        assert url == "https://callback.example.com/abc123"

    def test_create_callback_url_strips_slash(self):
        url = create_callback_url("https://callback.example.com/", "xyz")
        assert url == "https://callback.example.com/xyz"
