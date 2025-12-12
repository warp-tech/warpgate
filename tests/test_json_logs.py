"""
Integration tests for JSON log output format.
Tests that log.format: json configuration produces valid JSON logs.

This test is standalone and can be run independently of the poetry setup.
Run with: python -m pytest tests/test_json_logs.py -v
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

import pytest
import requests
import yaml

# Standalone utilities (copied from util.py to avoid import issues)
_allocated_ports = set()


def alloc_port():
    """Allocate a unique port for testing."""
    import socket
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
            if port not in _allocated_ports:
                _allocated_ports.add(port)
                return port


def wait_port(port, for_process=None, recv=True, timeout=30):
    """Wait for a port to become available."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        if for_process and for_process.poll() is not None:
            raise Exception(f"Process exited with code {for_process.returncode}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(('localhost', port))
                if recv:
                    s.recv(1)
                return
        except (socket.error, socket.timeout):
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} not available after {timeout}s")


# Determine binary path
cargo_root = Path(os.getcwd())
if (cargo_root / "tests").exists():
    cargo_root = cargo_root  # Running from repo root
elif (cargo_root.parent / "tests").exists():
    cargo_root = cargo_root.parent  # Running from tests dir

binary_path = "target/debug/warpgate"


class TestJsonLogs:
    """Test JSON log output format."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_json_logs_via_config(self, temp_dir):
        """Test that log.format: json in config produces JSON output."""
        # Set up ports
        ssh_port = alloc_port()
        http_port = alloc_port()
        mysql_port = alloc_port()
        postgres_port = alloc_port()

        data_dir = temp_dir / f"wg-json-logs-{uuid4()}"
        data_dir.mkdir(parents=True)

        # Copy required files from tests directory
        tests_dir = cargo_root / "tests"
        keys_dir = data_dir / "ssh-keys"
        keys_dir.mkdir(parents=True)
        for k in [
            tests_dir / "ssh-keys/wg/client-ed25519",
            tests_dir / "ssh-keys/wg/client-rsa",
            tests_dir / "ssh-keys/wg/host-ed25519",
            tests_dir / "ssh-keys/wg/host-rsa",
        ]:
            shutil.copy(k, keys_dir / k.name)

        for k in [
            tests_dir / "certs/tls.certificate.pem",
            tests_dir / "certs/tls.key.pem",
        ]:
            shutil.copy(k, data_dir / k.name)

        config_path = data_dir / "warpgate.yaml"
        log_output_path = data_dir / "warpgate.log"

        # Run unattended setup first
        setup_result = subprocess.run(
            [
                os.path.join(cargo_root, binary_path),
                "--config",
                str(config_path),
                "unattended-setup",
                "--ssh-port",
                str(ssh_port),
                "--http-port",
                str(http_port),
                "--mysql-port",
                str(mysql_port),
                "--postgres-port",
                str(postgres_port),
                "--data-path",
                str(data_dir),
                "--external-host",
                "localhost",
            ],
            cwd=cargo_root,
            env={
                **os.environ,
                "WARPGATE_ADMIN_PASSWORD": "test123",
            },
            capture_output=True,
        )
        assert setup_result.returncode == 0, f"Setup failed: {setup_result.stderr.decode()}"

        # Modify config to enable JSON logs
        config = yaml.safe_load(config_path.open())
        config["ssh"]["host_key_verification"] = "auto_accept"
        config["log"] = config.get("log", {})
        config["log"]["format"] = "json"
        with config_path.open("w") as f:
            yaml.safe_dump(config, f)

        # Start Warpgate with stdout captured
        with open(log_output_path, "w") as log_file:
            wg_process = subprocess.Popen(
                [
                    os.path.join(cargo_root, binary_path),
                    "--config",
                    str(config_path),
                    "run",
                ],
                cwd=cargo_root,
                env={
                    **os.environ,
                    "WARPGATE_ADMIN_TOKEN": "token-value",
                },
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )

            try:
                # Wait for Warpgate to start
                wait_port(http_port, for_process=wg_process, recv=False)

                # Give it a moment to log some messages
                time.sleep(1)

                # Make a request to generate more logs
                session = requests.Session()
                session.verify = False
                try:
                    session.get(f"https://localhost:{http_port}/", timeout=5)
                except Exception:
                    pass  # Expected to fail without proper auth, but will generate logs

                # Give it a moment to write logs
                time.sleep(0.5)

            finally:
                # Stop Warpgate
                wg_process.terminate()
                try:
                    wg_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    wg_process.kill()

        # Read and validate log output
        log_content = log_output_path.read_text()
        lines = [line.strip() for line in log_content.split("\n") if line.strip()]

        assert len(lines) > 0, "No log output captured"

        # Validate each line is valid JSON
        json_entries = []
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
                json_entries.append(entry)
            except json.JSONDecodeError as e:
                pytest.fail(f"Line {i+1} is not valid JSON: {line[:100]}... Error: {e}")

        # Validate structure of at least one entry
        assert len(json_entries) > 0, "No JSON log entries found"

        # Check that entries have required fields
        for entry in json_entries:
            assert "timestamp" in entry, f"Missing 'timestamp' field in: {entry}"
            assert "level" in entry, f"Missing 'level' field in: {entry}"
            assert "target" in entry, f"Missing 'target' field in: {entry}"
            assert "message" in entry, f"Missing 'message' field in: {entry}"

            # Validate timestamp format (ISO 8601)
            assert "T" in entry["timestamp"], f"Invalid timestamp format: {entry['timestamp']}"

            # Validate level is lowercase
            assert entry["level"] in ["trace", "debug", "info", "warn", "error"], \
                f"Invalid level: {entry['level']}"

            # Validate target starts with warpgate
            assert entry["target"].startswith("warpgate"), \
                f"Target should start with 'warpgate': {entry['target']}"

    def test_json_logs_via_cli(self, temp_dir):
        """Test that --log-format json CLI flag produces JSON output."""
        # Set up ports
        ssh_port = alloc_port()
        http_port = alloc_port()
        mysql_port = alloc_port()
        postgres_port = alloc_port()

        data_dir = temp_dir / f"wg-json-cli-{uuid4()}"
        data_dir.mkdir(parents=True)

        # Copy required files from tests directory
        tests_dir = cargo_root / "tests"
        keys_dir = data_dir / "ssh-keys"
        keys_dir.mkdir(parents=True)
        for k in [
            tests_dir / "ssh-keys/wg/client-ed25519",
            tests_dir / "ssh-keys/wg/client-rsa",
            tests_dir / "ssh-keys/wg/host-ed25519",
            tests_dir / "ssh-keys/wg/host-rsa",
        ]:
            shutil.copy(k, keys_dir / k.name)

        for k in [
            tests_dir / "certs/tls.certificate.pem",
            tests_dir / "certs/tls.key.pem",
        ]:
            shutil.copy(k, data_dir / k.name)

        config_path = data_dir / "warpgate.yaml"
        log_output_path = data_dir / "warpgate.log"

        # Run unattended setup
        setup_result = subprocess.run(
            [
                os.path.join(cargo_root, binary_path),
                "--config",
                str(config_path),
                "unattended-setup",
                "--ssh-port",
                str(ssh_port),
                "--http-port",
                str(http_port),
                "--mysql-port",
                str(mysql_port),
                "--postgres-port",
                str(postgres_port),
                "--data-path",
                str(data_dir),
                "--external-host",
                "localhost",
            ],
            cwd=cargo_root,
            env={
                **os.environ,
                "WARPGATE_ADMIN_PASSWORD": "test123",
            },
            capture_output=True,
        )
        assert setup_result.returncode == 0, f"Setup failed: {setup_result.stderr.decode()}"

        # Modify config (but don't set JSON format - we'll use CLI)
        config = yaml.safe_load(config_path.open())
        config["ssh"]["host_key_verification"] = "auto_accept"
        with config_path.open("w") as f:
            yaml.safe_dump(config, f)

        # Start Warpgate with --log-format json CLI flag
        with open(log_output_path, "w") as log_file:
            wg_process = subprocess.Popen(
                [
                    os.path.join(cargo_root, binary_path),
                    "--config",
                    str(config_path),
                    "--log-format",
                    "json",
                    "run",
                ],
                cwd=cargo_root,
                env={
                    **os.environ,
                    "WARPGATE_ADMIN_TOKEN": "token-value",
                },
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )

            try:
                # Wait for Warpgate to start
                wait_port(http_port, for_process=wg_process, recv=False)
                time.sleep(1)

            finally:
                wg_process.terminate()
                try:
                    wg_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    wg_process.kill()

        # Read and validate log output
        log_content = log_output_path.read_text()
        lines = [line.strip() for line in log_content.split("\n") if line.strip()]

        assert len(lines) > 0, "No log output captured"

        # Validate at least first line is valid JSON
        first_line = lines[0]
        try:
            entry = json.loads(first_line)
            assert "timestamp" in entry
            assert "level" in entry
            assert "target" in entry
            assert "message" in entry
        except json.JSONDecodeError as e:
            pytest.fail(f"First line is not valid JSON: {first_line[:100]}... Error: {e}")
