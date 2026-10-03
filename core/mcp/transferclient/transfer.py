#!/usr/bin/env python3
"""Optional standard-library client for XOps prepared HTTP transfers.

Task JSON contains a short-lived credential. Keep that file private and delete
it after use. No credentials or remote scripts are accepted on the command line.
"""

import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import socket
import stat
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit


class TransferError(Exception):
    pass


def origin(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise TransferError("invalid transfer origin")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise TransferError("invalid transfer port") from exc
    return parsed.scheme, parsed.hostname.lower(), port


def load_task(filename, server, operation):
    with open(filename, "rb") as source:
        data = source.read(65537)
    if len(data) > 65536:
        raise TransferError("task JSON exceeds size limit")
    prepared = json.loads(data)
    if not isinstance(prepared, dict) or not isinstance(prepared.get("task"), dict):
        raise TransferError("task JSON must contain an object named task")
    task = prepared.get("task", {})
    task_id = task.get("transferID", "")
    if not isinstance(task_id, str) or not re.fullmatch(r"[0-9a-f]{32}", task_id):
        raise TransferError("invalid transfer ID")
    expected = origin(server)
    if urlsplit(server).path not in ("", "/"):
        raise TransferError("--server must be an origin without a path")
    base_path = "/v1/transfers/" + task_id
    for field, path in (("statusURL", base_path), ("url", base_path + "/content")):
        value = prepared.get(field, "")
        if not isinstance(value, str) or origin(value) != expected or urlsplit(value).path != path:
            raise TransferError("task URL does not match the configured server and task")
    headers = prepared.get("headers", {})
    if not isinstance(headers, dict):
        raise TransferError("task headers must be an object")
    auth = headers.get("Authorization", "")
    if not isinstance(auth, str) or not re.fullmatch(r"Bearer [0-9a-f]{64}", auth):
        raise TransferError("invalid task credential")
    size = task.get("size")
    if type(size) is not int or size < 0 or size > 1 << 50:
        raise TransferError("invalid task file size")
    if operation != "status":
        method = "PUT" if operation == "upload" else "GET"
        if task.get("direction") != operation or prepared.get("method") != method:
            raise TransferError("task direction does not match the requested operation")
        if task.get("state") != "ready":
            raise TransferError("task is not ready; query its status instead of repeating data transfer")
    return prepared


class Client:
    def __init__(self, prepared, idle, total, ca_file=None):
        if not math.isfinite(idle) or not math.isfinite(total) or idle <= 0 or total <= 0:
            raise TransferError("timeouts must be positive")
        self.prepared = prepared
        self.idle = idle
        self.deadline = time.monotonic() + total
        self.ca_file = ca_file

    def connect(self, url, control=False, control_timeout=10):
        parsed = urlsplit(url)
        scheme, host, port = origin(url)
        timeout = min(self.idle, control_timeout) if control else self.remaining()
        if scheme == "https":
            context = ssl.create_default_context(cafile=self.ca_file)
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        return connection, parsed

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TransferError("client transfer deadline exceeded")
        return min(self.idle, left)

    def begin(self, connection, parsed, method, size=None):
        connection.putrequest(method, parsed.path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", parsed.netloc)
        connection.putheader("Authorization", self.prepared["headers"]["Authorization"])
        if size is not None:
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Content-Length", str(size))
        connection.endheaders()

    def refresh_timeout(self, connection):
        timeout = self.remaining()
        if connection.sock is not None:
            connection.sock.settimeout(timeout)

    @contextmanager
    def response_deadline(self, connection, deadline=None):
        # A socket timeout only bounds individual receives. HTTPResponse may
        # perform many receives inside read(), readline() or chunk decoding.
        # Keep the actual socket: getresponse() detaches it from connection
        # for Connection: close responses, while its file object still reads it.
        left = (self.deadline if deadline is None else deadline) - time.monotonic()
        if left <= 0:
            raise TransferError("client HTTP exchange deadline exceeded")
        transport = connection.sock
        expired = threading.Event()

        def interrupt():
            expired.set()
            if transport is not None:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Completion may already have closed this socket.

        timer = threading.Timer(left, interrupt)
        timer.daemon = True
        timer.start()
        try:
            yield
        finally:
            timer.cancel()
            timer.join()
            if expired.is_set():
                raise TransferError("client HTTP exchange deadline exceeded")

    def status(self, timeout=10):
        deadline = time.monotonic() + timeout
        connection, parsed = self.connect(self.prepared["statusURL"], control=True, control_timeout=timeout)
        try:
            self.begin(connection, parsed, "GET")
            with self.response_deadline(connection, deadline):
                with connection.getresponse() as response:
                    if response.status != 200:
                        raise TransferError("status lookup failed; use xops_transfer_status")
                    body = response.read(65537)
                    if len(body) > 65536:
                        raise TransferError("status response exceeds size limit")
                    task = json.loads(body)["task"]
                    if task.get("transferID") != self.prepared["task"]["transferID"]:
                        raise TransferError("status response belongs to a different task")
                    return task
        finally:
            connection.close()

    def wait_status(self):
        # Receiving the last byte may precede the server's final journal fsync.
        # Only status requests are repeated; the data request is never replayed.
        deadline = time.monotonic() + 45
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransferError("server outcome is still pending; query status before proceeding")
            task = self.status(min(10, remaining))
            if task.get("state") not in ("transferring", "verifying", "committing"):
                return task
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))

    def upload(self, filename):
        expected = self.prepared["task"]["size"]
        digest = hashlib.sha256()
        sent = 0
        failure = None
        with open(filename, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != expected:
                raise TransferError("local source is not a regular file of the approved size")
            connection, parsed = self.connect(self.prepared["url"])
            try:
                self.begin(connection, parsed, "PUT", expected)
                with self.response_deadline(connection):
                    while sent < expected:
                        data = source.read(min(65536, expected - sent))
                        if not data:
                            raise TransferError("local source became shorter during upload")
                        digest.update(data)
                        sent += len(data)
                        self.refresh_timeout(connection)
                        connection.send(data)
                    if source.read(1):
                        raise TransferError("local source grew during upload")
                    self.refresh_timeout(connection)
                    with connection.getresponse() as response:
                        response.read(65537)
                        if response.status != 200:
                            failure = TransferError("data endpoint did not confirm upload")
            except (OSError, http.client.HTTPException, TransferError) as exc:
                failure = exc
            finally:
                connection.close()
        # A lost response does not prove failure. Query once; never send again.
        task = self.wait_status()
        if (
            sent == expected
            and task.get("state") == "completed"
            and task.get("bytes") == expected
            and task.get("sha256") == digest.hexdigest()
        ):
            return task
        raise TransferError("upload is not confirmed; inspect task status before any new upload") from failure

    def download(self, filename, overwrite=False):
        destination = Path(filename)
        if not overwrite and os.path.lexists(destination):
            raise TransferError("local destination already exists")
        fd, temporary = tempfile.mkstemp(prefix=".xops-download-", dir=destination.parent)
        expected = self.prepared["task"]["size"]
        digest = hashlib.sha256()
        received = 0
        try:
            with os.fdopen(fd, "wb") as output:
                connection, parsed = self.connect(self.prepared["url"])
                try:
                    self.begin(connection, parsed, "GET")
                    with self.response_deadline(connection):
                        with connection.getresponse() as response:
                            if response.status != 200:
                                raise TransferError("download data request failed")
                            if response.getheader("Content-Length") != str(expected):
                                raise TransferError("download length header differs from the prepared task")
                            while True:
                                self.refresh_timeout(connection)
                                data = response.read(65536)
                                if not data:
                                    break
                                received += len(data)
                                if received > expected:
                                    raise TransferError("download exceeds approved length")
                                output.write(data)
                                digest.update(data)
                    output.flush()
                    os.fsync(output.fileno())
                finally:
                    connection.close()
            task = self.wait_status()
            if (
                received != expected
                or task.get("state") != "streamed"
                or task.get("bytes") != received
                or task.get("sha256") != digest.hexdigest()
            ):
                raise TransferError("download verification failed; local destination was preserved")
            if overwrite:
                os.replace(temporary, destination)
            else:
                # Same-directory hard-link publication is atomic and cannot
                # overwrite a destination that appeared after the initial check.
                os.link(temporary, destination)
                try:
                    os.unlink(temporary)
                except OSError:
                    # Publication already succeeded. Do not turn a cleanup
                    # failure into a misleading "download failed" result.
                    leftover = temporary
                    temporary = None
                    return dict(task, localSaved=True, clientCleanupPending=True, temporaryPath=leftover)
            temporary = None
            return dict(task, localSaved=True)
        finally:
            if temporary is not None:
                os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("upload", "download", "status"))
    parser.add_argument("--task", required=True, help="private JSON file containing the prepare tool result")
    parser.add_argument("--server", required=True, help="expected HTTP(S) origin from the MCP configuration")
    parser.add_argument("--file", help="explicit client-local file path")
    parser.add_argument("--overwrite-local", action="store_true")
    parser.add_argument("--idle-timeout", type=float, default=60)
    parser.add_argument("--timeout", type=float, default=7200)
    parser.add_argument("--ca-file", help="optional trusted CA bundle for HTTPS")
    args = parser.parse_args()
    if args.operation != "status" and not args.file:
        parser.error("--file is required for upload/download")
    if args.overwrite_local and args.operation != "download":
        parser.error("--overwrite-local applies only to downloads")
    try:
        prepared = load_task(args.task, args.server, args.operation)
        client = Client(prepared, args.idle_timeout, args.timeout, args.ca_file)
        if args.operation == "upload":
            result = client.upload(args.file)
        elif args.operation == "download":
            result = client.download(args.file, args.overwrite_local)
        else:
            result = client.status()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (TransferError, OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
        # Exception strings from HTTP implementations may include response data.
        # Only our fixed messages are safe to print; never print task headers.
        message = str(exc) if isinstance(exc, TransferError) else "local I/O, task data or HTTP exchange failed"
        print(message + "; do not automatically repeat the data request", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
