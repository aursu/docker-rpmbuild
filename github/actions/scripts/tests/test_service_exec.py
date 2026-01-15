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
        """Initialize test fixtures before each test case execution."""
        self.config = MagicMock()
        self.config.runner_home = "/tmp"
        self.config.setup_timeout = 60

        self.service = runner.RunnerService(self.config, MagicMock(), MagicMock())

    @patch('sys.stdout', new_callable=StringIO)
    def test_exec_successful_command(self, mock_stdout):
        """Test successful command execution with output capture"""
        # Execute real subprocess with expected successful exit code
        return_code = self.service._exec(["/bin/echo", "Hello Real World!"])

        self.assertEqual(return_code, 0)

        output = mock_stdout.getvalue()
        self.assertIn("Hello Real World!", output)

    def test_exec_binary_not_found(self):
        """Test FileNotFoundError handling for missing binary"""

        # Attempt execution with non-existent binary path
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/nonexistent/binary"])

        # Verify error message content
        self.assertIn("Binary not found", str(cm.exception))
        self.assertIn("/nonexistent/binary", str(cm.exception))

    def test_exec_handles_no_output(self):
        """Test command with no output (silent success)"""

        # Execute command that produces no output
        result = self.service._exec(["/usr/bin/true"])

        # Verify successful completion without errors
        self.assertEqual(result, 0)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.sleep')
    def test_run_uses_configured_delay_integration(self, mock_sleep, mock_select, mock_popen):
        """
        Integration-like test: verify sleep is called between two subprocess executions.
        1st execution -> Exit Code 2 (Retry)
        2nd execution -> Exit Code 0 (Success)
        """
        # Configure retry delay (simulating environment variable)
        self.config.retry_delay = 42

        # Prepare two distinct subprocess behaviors

        # First process: exits with retryable error code 2
        proc_retry = MagicMock()
        proc_retry.poll.return_value = 2
        proc_retry.stdout.fileno.return_value = 1
        proc_retry.stdout.readline.return_value = ""  # Immediate EOF to prevent read loop iteration

        # Second process: exits successfully with code 0
        proc_success = MagicMock()
        proc_success.poll.return_value = 0
        proc_success.stdout.fileno.return_value = 1
        proc_success.stdout.readline.return_value = ""  # Immediate EOF

        # Configure Popen context manager behavior
        # When 'with subprocess.Popen(...) as p:' is invoked,
        # Python calls __enter__(). Configure side_effect to return
        # proc_retry on first call and proc_success on second call.
        mock_popen.return_value.__enter__.side_effect = [proc_retry, proc_success]
        mock_popen.return_value.__exit__.return_value = None

        # Configure select to avoid file descriptor errors
        mock_select.return_value = ([1], [], [])

        # Execute run loop (blocking real signal handling)
        with patch('runner.SignalHandler') as mock_signal:
            mock_signal.return_value.__enter__.return_value.shutdown_requested = False

            self.service.run()

        # Verify behavior

        # Verify sleep was called with configured delay value
        mock_sleep.assert_called_once_with(42)

        # Verify Popen was invoked twice (actual restart occurred)
        self.assertEqual(mock_popen.call_count, 2)

class TestRunnerServiceExec(unittest.TestCase):
    """
    Unit tests for RunnerService._exec() method.
    Tests subprocess execution, timeout handling, and error output capture.
    """

    def setUp(self):
        """Initialize test fixtures before each test case execution."""
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
        # Configure mock process to return successful exit code
        mock_proc = MagicMock()
        # After each select iteration, poll may be called. readline returns data twice, then end-of-file.
        # Final poll occurs after context manager exits.
        mock_proc.poll.return_value = 0  # Always return exit code 0 (success)
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Line 1\n",
            "Line 2\n",
            ""  # End-of-file marker terminates read loop
        ]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure select to indicate output stream has data available
        mock_select.side_effect = [
            ([1], [], []),  # Output available for Line 1
            ([1], [], []),  # Output available for Line 2
            ([1], [], [])   # End-of-file condition
        ]

        # Execute command under test
        result = self.service._exec(["/bin/echo", "test"])

        # Verify successful execution
        self.assertEqual(result, 0)
        mock_popen.assert_called_once()

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_command_failure_with_error_context(self, mock_select, mock_popen):
        """Test command failure captures error context"""
        # Configure mock process to return failure exit code with error output
        mock_proc = MagicMock()
        # Always return exit code 1 (failure)
        mock_proc.poll.return_value = 1
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Error: Configuration failed\n",
            "Invalid token provided\n",
            ""  # End-of-file marker
        ]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure select to indicate output stream has data available
        mock_select.side_effect = [
            ([1], [], []),  # Output available for error line 1
            ([1], [], []),  # Output available for error line 2
            ([1], [], [])   # End-of-file condition
        ]

        # Execute command and verify RunnerError exception is raised
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/bin/false"])

        # Verify error message includes captured output context
        error_msg = str(cm.exception)
        self.assertIn("Command failed (Code 1)", error_msg)
        self.assertIn("Error: Configuration failed", error_msg)
        self.assertIn("Invalid token provided", error_msg)

    @patch('runner.logger')
    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_timeout_handling(self, mock_time, mock_select, mock_popen, _):
        """Test timeout handling terminates process and returns correct exit code"""
        # Configure mock process to exceed timeout duration
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process never terminates naturally
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.return_value = "Still running...\n"
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = MagicMock()

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure time progression to trigger timeout condition
        mock_time.side_effect = [
            0.0,     # Initial start time
            5.0,     # First iteration - within timeout boundary
            15.0,    # Second iteration - exceeds 10 second timeout
        ]

        # Configure select to indicate output stream has data available
        mock_select.return_value = ([1], [], [])

        # Execute command with 10 second timeout constraint
        result = self.service._exec(["/bin/sleep", "100"], timeout=10)

        # Verify timeout behavior and exit code
        self.assertEqual(result, runner.RunnerExitCode.TERMINATED_ERROR)
        mock_proc.terminate.assert_called_once()

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_timeout_with_error_output(self, mock_time, mock_select, mock_popen):
        """Test timeout includes captured output in error log"""
        # Configure mock process that produces output before timeout occurs
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process never terminates naturally
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = [
            "Processing item 1...\n",
            "Processing item 2...\n",
            "Processing item 3...\n"
        ]
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = MagicMock()

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure time progression to trigger timeout
        mock_time.side_effect = [0.0, 5.0, 15.0]

        # Configure select to indicate output stream has data available
        mock_select.side_effect = [
            ([1], [], []),
            ([1], [], []),
            ([1], [], []),
        ]

        with patch('runner.logger') as mock_logger:
            self.service._exec(["/bin/command"], timeout=10)

            # Verify logger.error was invoked with captured output context
            self.assertTrue(mock_logger.error.called)

            args, _ = mock_logger.error.call_args
            error_call = args[0]

            self.assertIn("timed out after 10s", error_call)
            self.assertIn("Last output:", error_call)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_captures_last_n_lines(self, mock_select, mock_popen):
        """Test that error context is bounded to last N lines"""
        # Configure mock process to generate extensive output
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1  # Exit with failure code
        mock_proc.stdout.fileno.return_value = 1

        # Generate output exceeding ERROR_LOG_SIZE capacity (50 lines)
        lines = [f"Line {i}\n" for i in range(100)] + [""]
        mock_proc.stdout.readline.side_effect = lines

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure select to indicate output stream has data available
        mock_select.return_value = ([1], [], [])

        # Execute command and verify failure exception is raised
        with self.assertRaises(runner.RunnerError) as cm:
            self.service._exec(["/bin/command"])

        error_msg = str(cm.exception)
        # Verify only most recent 50 lines are preserved in error context
        self.assertIn("Line 99", error_msg)  # Most recent line (100th, index 99)
        self.assertIn("Line 50", error_msg)  # 50th most recent line (oldest preserved)
        self.assertNotIn("Line 49", error_msg)  # 51st most recent line (excluded from buffer)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    def test_exec_handles_no_output(self, mock_select, mock_popen):
        """Test command with no output (silent success)"""
        # Configure mock process for silent successful execution
        mock_proc = MagicMock()
        mock_proc.poll.side_effect = [None, 0, 0]  # Process running, then exits successfully, then final status check
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.return_value = ""  # No output produced

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure select to indicate no data available (timeout)
        mock_select.return_value = ([], [], [])

        # Execute command under test
        result = self.service._exec(["/bin/true"])

        # Verify successful completion without errors
        self.assertEqual(result, 0)

    @patch('runner.subprocess.Popen')
    @patch('runner.select.select')
    @patch('runner.time.time')
    def test_exec_respects_io_poll_interval(self, mock_time, mock_select, mock_popen):
        """Test that _exec uses IO_POLL_INTERVAL when no timeout specified"""
        # Configure mock process for execution without timeout constraint
        mock_proc = MagicMock()
        # Always return exit code 0 (success)
        mock_proc.poll.return_value = 0
        mock_proc.stdout.fileno.return_value = 1
        mock_proc.stdout.readline.side_effect = ["output\n", ""]

        mock_popen.return_value.__enter__.return_value = mock_proc
        mock_popen.return_value.__exit__.return_value = None

        # Configure time mock without timeout specification
        mock_time.return_value = 0.0

        # Configure select to return data availability
        mock_select.side_effect = [
            ([1], [], []),  # Output available
            ([1], [], [])   # End-of-file condition
        ]

        # Execute command without timeout parameter
        self.service._exec(["/bin/command"])

        # Verify all select invocations use IO_POLL_INTERVAL (1.0s) as wait duration
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