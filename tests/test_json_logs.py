"""
Integration tests for JSON log output format.
Tests that log.format: json configuration produces valid JSON logs.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path

import requests
import yaml

from .conftest import ProcessManager
from .util import wait_port


class Test:
    """Test JSON log output format."""

    def test_json_logs_via_config(
        self,
        processes: ProcessManager,
        timeout,
    ):
        """Test that log.format: json in config produces JSON output."""
        # Create a temporary file to capture log output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as log_file:
            log_output_path = Path(log_file.name)

        try:
            # Start Warpgate to do initial setup (this creates config)
            wg = processes.start_wg()
            wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

            # Stop the process so we can modify the config
            wg.process.terminate()
            try:
                wg.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wg.process.kill()
                wg.process.wait()

            # Modify config to enable JSON logs
            config = yaml.safe_load(wg.config_path.open())
            config["log"] = config.get("log", {})
            config["log"]["format"] = "json"
            with wg.config_path.open("w") as f:
                yaml.safe_dump(config, f)

            # Restart Warpgate with JSON log config, capturing stdout
            with open(log_output_path, "w") as log_capture:
                wg_json = processes.start_wg(
                    share_with=wg,
                    args=["run", "--enable-admin-token"],
                    stdout=log_capture,
                    stderr=subprocess.STDOUT,
                )

                # Wait for Warpgate to start
                wait_port(wg_json.http_port, for_process=wg_json.process, recv=False, timeout=timeout)

                # Give it a moment to log startup messages
                time.sleep(1)

                # Make a request to generate more logs
                session = requests.Session()
                session.verify = False
                try:
                    session.get(f"https://localhost:{wg_json.http_port}/", timeout=5)
                except Exception:
                    pass  # Expected to fail without proper auth, but will generate logs

                # Give it a moment to write logs
                time.sleep(0.5)

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
                    raise AssertionError(f"Line {i+1} is not valid JSON: {line[:100]}... Error: {e}")

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

        finally:
            # Clean up temp file
            log_output_path.unlink(missing_ok=True)

    def test_json_logs_via_cli(
        self,
        processes: ProcessManager,
        timeout,
    ):
        """Test that --log-format json CLI flag produces JSON output."""
        # Create a temporary file to capture log output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as log_file:
            log_output_path = Path(log_file.name)

        try:
            # Start Warpgate to do initial setup (this creates config)
            # We need to do setup first without capturing stdout, because
            # start_wg passes stdout to both setup and run phases
            wg = processes.start_wg()
            wait_port(wg.http_port, for_process=wg.process, recv=False, timeout=timeout)

            # Stop the process so we can restart with CLI flag
            wg.process.terminate()
            try:
                wg.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wg.process.kill()
                wg.process.wait()

            # Restart Warpgate with --log-format json CLI flag, capturing stdout
            with open(log_output_path, "w") as log_capture:
                wg_json = processes.start_wg(
                    share_with=wg,
                    args=["--log-format", "json", "run", "--enable-admin-token"],
                    stdout=log_capture,
                    stderr=subprocess.STDOUT,
                )

                # Wait for Warpgate to start
                wait_port(wg_json.http_port, for_process=wg_json.process, recv=False, timeout=timeout)

                # Give it a moment to log startup messages
                time.sleep(1)

            # Read and validate log output
            log_content = log_output_path.read_text()
            lines = [line.strip() for line in log_content.split("\n") if line.strip()]

            assert len(lines) > 0, "No log output captured"

            # Validate at least first line is valid JSON with required fields
            first_line = lines[0]
            try:
                entry = json.loads(first_line)
                assert "timestamp" in entry, f"Missing 'timestamp' field"
                assert "level" in entry, f"Missing 'level' field"
                assert "target" in entry, f"Missing 'target' field"
                assert "message" in entry, f"Missing 'message' field"
            except json.JSONDecodeError as e:
                raise AssertionError(f"First line is not valid JSON: {first_line[:100]}... Error: {e}")

        finally:
            # Clean up temp file
            log_output_path.unlink(missing_ok=True)
