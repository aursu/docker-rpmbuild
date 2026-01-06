#!/usr/bin/env python3
from io import StringIO
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock

# Import from parent directory (runner module)
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner

class TestRunnerServiceExecIntegration(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures"""
        self.config = MagicMock()
        self.config.runner_home = "/tmp"
        self.config.setup_timeout = 60

        self.service = runner.RunnerService(self.config, None, None)

    @patch('sys.stdout', new_callable=StringIO)
    def test_exec_successful_command(self, mock_stdout):
        """Test successful command execution with output capture"""
        # Mock process that returns success
        return_code = self.service._exec(["/bin/echo", "Hello Real World!"])

        self.assertEqual(return_code, 0)

        output = mock_stdout.getvalue()
        self.assertIn("Hello Real World!", output)

    def test_exec_binary_not_found(self):
        """Test FileNotFoundError handling for missing binary"""

        # Execute command with non-existent binary
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/nonexistent/binary"])

        # Verify error message
        self.assertIn("Binary not found", str(cm.exception))
        self.assertIn("/nonexistent/binary", str(cm.exception))

    def test_exec_handles_no_output(self):
        """Test command with no output (silent success)"""

        # Execute
        result = self.service._exec(["/usr/bin/true"])

        # Should succeed without errors
        self.assertEqual(result, 0)

class TestRunnerServiceExec(unittest.TestCase):
    """
    Unit tests for RunnerService._exec() method.
    Tests subprocess execution, timeout handling, and error output capture.
    """

    def setUp(self):
        """Set up test fixtures"""
        self.config = MagicMock()
        self.config.runner_home = "/tmp"
        self.config.setup_timeout = 60

        self.fman = MagicMock()
        self.github = MagicMock()

        self.service = runner.RunnerService(self.config, self.fman, self.github)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_successful_command(self, mock_select, mock_popen):
        """Test successful command execution with output capture"""
        # Mock process that returns success
        mock_proc = MagicMock()
        # After each select we may poll. readline returns data twice, then EOF.
        # Then final poll after with block exits.
        mock_proc.poll.return_value = 0  # Always return 0 (success)
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Line 1\n",
            "Line 2\n",
            ""  # EOF - breaks loop
        ]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock select to indicate data is ready
        mock_select.side_effect = [
            ([1], [], []),  # Data ready - Line 1
            ([1], [], []),  # Data ready - Line 2
            ([1], [], [])   # EOF
        ]

        # Execute command
        result = self.service._exec(["/bin/echo", "test"])

        # Verify success
        self.assertEqual(result, 0)
        mock_popen.assert_called_once()

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_command_failure_with_error_context(self, mock_select, mock_popen):
        """Test command failure captures error context"""
        # Mock process that fails with error output
        mock_proc = MagicMock()
        # Always return 1 (failure)
        mock_proc.poll.return_value = 1
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Error: Configuration failed\n",
            "Invalid token provided\n",
            ""  # EOF
        ]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock select to indicate data is ready
        mock_select.side_effect = [
            ([1], [], []),  # Data ready
            ([1], [], []),  # Data ready
            ([1], [], [])   # EOF
        ]

        # Execute command and expect RunnerError
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/bin/false"])

        # Verify error message contains output context
        error_msg = str(cm.exception)
        self.assertIn("Command failed (Code 1)", error_msg)
        self.assertIn("Error: Configuration failed", error_msg)
        self.assertIn("Invalid token provided", error_msg)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_timeout_handling(self, mock_time, mock_select, mock_popen):
        """Test timeout handling terminates process and returns correct exit code"""
        # Mock process that runs too long
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.return_value = "Still running...\n"
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = MagicMock()

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock time progression to trigger timeout
        mock_time.side_effect = [
            0.0,     # start_time
            5.0,     # First check - within timeout
            15.0,    # Second check - exceeds 10s timeout
        ]

        # Mock select returns data ready
        mock_select.return_value = ([1], [], [])

        # Execute with 10 second timeout
        result = self.service._exec(["/bin/sleep", "100"], timeout=10)

        # Verify timeout handling
        self.assertEqual(result, runner.RunnerExitCode.TERMINATED_ERROR)
        mock_proc.terminate.assert_called_once()

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_timeout_with_error_output(self, mock_time, mock_select, mock_popen):
        """Test timeout includes captured output in error log"""
        # Mock process with output before timeout
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Processing item 1...\n",
            "Processing item 2...\n",
            "Processing item 3...\n"
        ] + ["Still processing...\n"] * 100  # Many lines
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = MagicMock()

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock time progression
        mock_time.side_effect = [0.0, 5.0, 15.0]

        # Mock select returns data ready
        mock_select.side_effect = [
            ([1], [], []),
            ([1], [], []),
            ([1], [], []),
        ]

        with patch('runner.logger') as mock_logger:
            result = self.service._exec(["/bin/command"], timeout=10)

            # Verify logger.error was called with output context
            self.assertTrue(mock_logger.error.called)

            args, _ = mock_logger.error.call_args
            error_call = args[0]

            self.assertIn("timed out after 10s", error_call)
            self.assertIn("Last output:", error_call)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_captures_last_n_lines(self, mock_select, mock_popen):
        """Test that error context is bounded to last N lines"""
        # Mock process with many lines of output
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.stdout.fileno.return_value = 1

        # Generate more lines than ERROR_LOG_SIZE (50)
        lines = [f"Line {i}\n" for i in range(100)] + [""]
        mock_proc.stdout.readline.side_effect = lines

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock select indicates data ready
        mock_select.return_value = ([1], [], [])

        # Execute and expect failure
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/bin/command"])

        error_msg = str(cm.exception)
        # Should contain last 50 lines only
        self.assertIn("Line 99", error_msg)  # Last line
        self.assertIn("Line 50", error_msg)  # 50th from end
        self.assertNotIn("Line 49", error_msg)  # Should be dropped (51st from end)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_handles_no_output(self, mock_select, mock_popen):
        """Test command with no output (silent success)"""
        # Mock silent successful process
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 0, 0]  # Running, then exit, then check
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.return_value = ""  # No output

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock select timeout (no data) then process exits
        mock_select.return_value = ([], [], [])

        # Execute
        result = self.service._exec(["/bin/true"])

        # Should succeed without errors
        self.assertEqual(result, 0)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_respects_io_poll_interval(self, mock_time, mock_select, mock_popen):
        """Test that _exec uses IO_POLL_INTERVAL when no timeout specified"""
        # Mock long-running process without timeout
        mock_proc = MagicMock()
        # Always return 0 (success)
        mock_proc.poll.return_value = 0
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = ["output\n", ""]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Mock time - no timeout specified
        mock_time.return_value = 0.0

        # Capture select call arguments
        mock_select.side_effect = [
            ([1], [], []),  # Data ready
            ([1], [], [])   # EOF
        ]

        # Execute without timeout
        self.service._exec(["/bin/command"])

        # All calls should use IO_POLL_INTERVAL (1.0s) when no timeout
        self.assertTrue(all(
            args[3] == runner.RunnerService.IO_POLL_INTERVAL
            for args, _ in mock_select.call_args_list
        ))

    def test_terminate_process_escalates_to_kill(self):
        """Test _terminate_process escalates to kill on timeout"""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()

        # Mock wait to timeout on terminate, succeed on kill
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd=[], timeout=5),  # Terminate timeout
            None  # Kill succeeds
        ]

        # Call terminate_process
        self.service._terminate_process(mock_proc)

        # Verify escalation sequence
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()
        self.assertEqual(mock_proc.wait.call_count, 2)

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)