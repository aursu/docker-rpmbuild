#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner

class TestSecuritySanitization(unittest.TestCase):
    """
    Tests for log sanitization and credential leakage prevention.
    """

    def setUp(self):
        self.config = MagicMock()
        self.service = runner.RunnerService(self.config, MagicMock(), MagicMock())

    def test_sanitize_args_masks_tokens(self):
        """Test that _sanitize_args correctly masks sensitive values"""
        raw_args = [
            "./Runner.Listener", "configure",
            "--token", "SUPER_SECRET_TOKEN_123",
            "--url", "https://github.com",
            "--name", "my-runner"
        ]

        expected = "./Runner.Listener configure --token *** --url https://github.com --name my-runner"
        result = self.service._sanitize_args(raw_args)

        self.assertEqual(result, expected)
        self.assertNotIn("SUPER_SECRET_TOKEN_123", result)

    def test_sanitize_args_multiple_sensitive_flags(self):
        """Test masking multiple sensitive flags in one command"""
        raw_args = ["--token", "SECRET1", "--pat", "SECRET2", "--verbose"]

        expected = "--token *** --pat *** --verbose"
        result = self.service._sanitize_args(raw_args)

        self.assertEqual(result, expected)

    def test_sanitize_args_flag_at_end(self):
        """Test robustness when sensitive flag is the last argument (invalid cmd, but shouldn't crash)"""
        raw_args = ["./run.sh", "--token"]

        expected = "./run.sh --token"
        result = self.service._sanitize_args(raw_args)

        self.assertEqual(result, expected)

    def test_sanitize_args_no_sensitive_data(self):
        """Test that normal commands are not modified"""
        raw_args = ["ls", "-la", "/home/runner"]
        result = self.service._sanitize_args(raw_args)
        self.assertEqual(result, "ls -la /home/runner")

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_timeout_logs_sanitized_command(self, mock_time, mock_select, mock_popen):
        """Test timeout includes captured output in error log"""
        # Configure mock process that produces output before timeout occurs
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process never terminates naturally
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.return_value = "Processing data...\n"
        mock_proc.wait = MagicMock()

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure time progression to trigger timeout
        # 20.0 - logger.error inside subprocess.TimeoutExpired handling uses time.time()
        mock_time.side_effect = [0.0, 5.0, 15.0, 20.0]

        # Configure select to indicate output stream has data available
        mock_select.return_value = ([1], [], [])

        with self.assertLogs('runner-ctl', level='ERROR') as cm:
            secret_token = "DO_NOT_LEAK_ME"
            cmd = ["./config.sh", "--token", secret_token]

            # Execute (expecting termination code)
            self.service._exec(cmd, timeout=10)

            log_message = cm.output[0]

            # Assertions
            self.assertIn("Command timed out", log_message)
            self.assertIn("--token ***", log_message)       # Must contain masked version
            self.assertNotIn(secret_token, log_message)     # Must NOT contain raw secret

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)