import hashlib
import importlib.util
import io
import json
import socketserver
import threading
import time
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("xops_transfer_client", Path(__file__).with_name("transfer.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def prepared(direction="download"):
    task_id = "1" * 32
    base = "http://127.0.0.1:8080/v1/transfers/" + task_id
    return {
        "task": {"transferID": task_id, "direction": direction, "size": 3, "state": "ready"},
        "url": base + "/content",
        "statusURL": base,
        "method": "GET" if direction == "download" else "PUT",
        "headers": {"Authorization": "Bearer " + "a" * 64},
    }


class Response(io.BytesIO):
    status = 200

    def getheader(self, name):
        return "3" if name == "Content-Length" else None


@contextmanager
def trickling_server(close_connection=False, slow_headers=False):
    stop = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(2)
            while self.rfile.readline(8192) not in (b"\r\n", b""):
                pass
            headers = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n"
            if close_connection:
                headers += b"Connection: close\r\n"
            headers += b"\r\n"
            try:
                if slow_headers:
                    for value in headers:
                        if stop.wait(0.03):
                            return
                        self.wfile.write(bytes([value]))
                else:
                    self.wfile.write(headers)
                for _ in range(20):
                    if stop.wait(0.05):
                        return
                    self.wfile.write(b"x")
            except (BrokenPipeError, ConnectionResetError):
                pass  # The client deliberately interrupts at its deadline.

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        worker.start()
        try:
            yield "http://127.0.0.1:" + str(server.server_address[1])
        finally:
            stop.set()
            server.shutdown()
            worker.join(timeout=3)
            if worker.is_alive():
                raise AssertionError("trickle server did not stop")


class ClientTests(unittest.TestCase):
    def test_download_total_deadline_interrupts_trickling_response(self):
        for closed, headers in ((False, False), (True, False), (False, True)):
            with self.subTest(connection_close=closed, slow_headers=headers), trickling_server(closed, headers) as server:
                task = prepared()
                task["task"]["size"] = 20
                task["url"] = task["url"].replace("http://127.0.0.1:8080", server)
                client = module.Client(task, 1, 0.15)
                with tempfile.TemporaryDirectory() as directory:
                    destination = Path(directory, "file")
                    destination.write_bytes(b"original")
                    start = time.monotonic()
                    with self.assertRaises((module.TransferError, OSError, module.http.client.HTTPException)):
                        client.download(destination, overwrite=True)
                    self.assertLess(time.monotonic() - start, 0.5)
                    self.assertEqual(destination.read_bytes(), b"original")
                    self.assertEqual(list(Path(directory).glob(".xops-download-*")), [])

    def test_status_total_deadline_interrupts_trickle(self):
        with trickling_server() as server:
            task = prepared()
            task["statusURL"] = task["statusURL"].replace("http://127.0.0.1:8080", server)
            client = module.Client(task, 1, 10)
            start = time.monotonic()
            with self.assertRaises(module.TransferError):
                client.status(timeout=0.15)
            self.assertLess(time.monotonic() - start, 0.5)

    def test_task_origin_mismatch_is_rejected(self):
        task = prepared()
        task["url"] = task["url"].replace("127.0.0.1", "attacker.invalid")
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory, "task.json")
            filename.write_text(json.dumps(task))
            with self.assertRaises(module.TransferError):
                module.load_task(filename, "http://127.0.0.1:8080", "download")

    def test_nonfinite_and_zero_timeouts_are_rejected(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(module.TransferError):
                module.Client(prepared(), timeout, 60)

    def test_existing_destination_does_not_consume_task(self):
        client = module.Client(prepared(), 5, 60)
        client.connect = Mock(side_effect=AssertionError("must not open a data request"))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "file")
            destination.write_bytes(b"old")
            with self.assertRaises(module.TransferError):
                client.download(destination)
            self.assertEqual(destination.read_bytes(), b"old")
        client.connect.assert_not_called()

    def test_bad_checksum_preserves_existing_file_and_cleans_temporary(self):
        client = module.Client(prepared(), 5, 60)
        connection = Mock()
        connection.getresponse.return_value = Response(b"abc")
        client.connect = Mock(return_value=(connection, module.urlsplit(prepared()["url"])))
        client.status = Mock(return_value={"state": "streamed", "bytes": 3, "sha256": "0" * 64})
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "file")
            destination.write_bytes(b"old")
            with self.assertRaises(module.TransferError):
                client.download(destination, overwrite=True)
            self.assertEqual(destination.read_bytes(), b"old")
            self.assertEqual(list(Path(directory).glob(".xops-download-*")), [])
        connection.close.assert_called_once()

    def test_lost_upload_response_queries_status_without_resending(self):
        task = prepared("upload")
        client = module.Client(task, 5, 60)
        connection = Mock()
        connection.getresponse.side_effect = ConnectionResetError("test response loss")
        client.connect = Mock(return_value=(connection, module.urlsplit(task["url"])))
        client.status = Mock(return_value={"state": "completed", "bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()})
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "file")
            source.write_bytes(b"abc")
            self.assertEqual(client.upload(source)["state"], "completed")
        connection.send.assert_called_once_with(b"abc")
        client.connect.assert_called_once()
        client.status.assert_called_once()

    def test_local_disk_full_preserves_destination(self):
        client = module.Client(prepared(), 5, 60)
        connection = Mock()
        connection.getresponse.return_value = Response(b"abc")
        client.connect = Mock(return_value=(connection, module.urlsplit(prepared()["url"])))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "file")
            destination.write_bytes(b"old")
            with patch.object(module.os, "fsync", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    client.download(destination, overwrite=True)
            self.assertEqual(destination.read_bytes(), b"old")
            self.assertEqual(list(Path(directory).glob(".xops-download-*")), [])
        connection.close.assert_called_once()

    def test_destination_created_during_download_is_not_clobbered(self):
        client = module.Client(prepared(), 5, 60)
        connection = Mock()
        connection.getresponse.return_value = Response(b"abc")
        client.connect = Mock(return_value=(connection, module.urlsplit(prepared()["url"])))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory, "file")
            def status(_timeout=10):
                destination.write_bytes(b"concurrent writer")
                return {"state": "streamed", "bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
            client.status = status
            with self.assertRaises(FileExistsError):
                client.download(destination)
            self.assertEqual(destination.read_bytes(), b"concurrent writer")
            self.assertEqual(list(Path(directory).glob(".xops-download-*")), [])

    def test_redirect_is_not_followed(self):
        client = module.Client(prepared(), 5, 60)
        connection = Mock()
        response = Response(b"")
        response.status = 302
        connection.getresponse.return_value = response
        client.connect = Mock(return_value=(connection, module.urlsplit(prepared()["url"])))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(module.TransferError):
                client.download(Path(directory, "file"))
            self.assertEqual(list(Path(directory).iterdir()), [])
        client.connect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
