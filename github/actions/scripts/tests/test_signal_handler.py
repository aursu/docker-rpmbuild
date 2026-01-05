#!/usr/bin/env python3
"""
Unit tests for SignalHandler context manager.

Tests verify signal handling behavior including:
- Signal handler installation and restoration
- Shutdown flag state management
- Context manager lifecycle
- Multiple signal handling scenarios
"""

import unittest
import signal
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner


class TestSignalHandler(unittest.TestCase):
    """
    Comprehensive tests for SignalHandler context manager.
    """

    def setUp(self):
        """Save current signal handlers before each test"""
        self.original_sigint = signal.getsignal(signal.SIGINT)
        self.original_sigterm = signal.getsignal(signal.SIGTERM)

    def tearDown(self):
        """Restore original signal handlers after each test"""
        signal.signal(signal.SIGINT, self.original_sigint)
        signal.signal(signal.SIGTERM, self.original_sigterm)

    def test_context_manager_enter(self):
        """Test that __enter__ installs signal handlers and saves originals"""
        handler = runner.SignalHandler()

        with handler:
            # Verify original handlers were saved
            self.assertIsNotNone(handler._original_sigint, "Original SIGINT handler should be saved")
            self.assertIsNotNone(handler._original_sigterm, "Original SIGTERM handler should be saved")

            # Verify new handlers are installed
            current_sigint = signal.getsignal(signal.SIGINT)
            current_sigterm = signal.getsignal(signal.SIGTERM)

            self.assertIsNotNone(current_sigint, "SIGINT handler should be installed")
            self.assertIsNotNone(current_sigterm, "SIGTERM handler should be installed")

            # Verify handlers point to the _handler method
            # Cannot directly compare bound methods, but we can verify they're not the originals
            self.assertNotEqual(current_sigint, self.original_sigint, "SIGINT handler should be replaced")
            self.assertNotEqual(current_sigterm, self.original_sigterm, "SIGTERM handler should be replaced")

    def test_context_manager_exit_restores_handlers(self):
        """Test that __exit__ restores original signal handlers"""
        handler = runner.SignalHandler()

        with handler:
            pass  # Exit context

        # Verify handlers are restored
        restored_sigint = signal.getsignal(signal.SIGINT)
        restored_sigterm = signal.getsignal(signal.SIGTERM)

        self.assertEqual(restored_sigint, self.original_sigint, "SIGINT handler should be restored")
        self.assertEqual(restored_sigterm, self.original_sigterm, "SIGTERM handler should be restored")

    @patch('runner.logger')
    def test_sigint_sets_shutdown_flag(self, mock_logger):
        """Test that SIGINT signal sets shutdown_requested flag"""
        handler = runner.SignalHandler()

        with handler:
            self.assertFalse(handler.shutdown_requested, "Flag should be False before signal")

            # Simulate SIGINT signal
            handler._handler(signal.SIGINT, None)

            self.assertTrue(handler.shutdown_requested, "Flag should be True after SIGINT")

            mock_logger.info.assert_called_once()
            args, _ = mock_logger.info.call_args
            self.assertIn("SIGINT", args[0])

    @patch('runner.logger')
    def test_sigterm_sets_shutdown_flag(self, mock_logger):
        """Test that SIGTERM signal sets shutdown_requested flag"""
        handler = runner.SignalHandler()

        with handler:
            self.assertFalse(handler.shutdown_requested, "Flag should be False before signal")

            # Simulate SIGTERM signal
            handler._handler(signal.SIGTERM, None)

            self.assertTrue(handler.shutdown_requested, "Flag should be True after SIGTERM")

            mock_logger.info.assert_called_once()
            args, _ = mock_logger.info.call_args
            self.assertIn("SIGTERM", args[0])

    @patch('runner.logger')
    def test_multiple_signals_handled(self, mock_logger):
        """Test that multiple signals are handled correctly"""
        handler = runner.SignalHandler()

        with handler:
            # First signal
            handler._handler(signal.SIGINT, None)
            self.assertTrue(handler.shutdown_requested, "Flag should be set after first signal")

            # Second signal (should not change state, already True)
            handler._handler(signal.SIGTERM, None)
            self.assertTrue(handler.shutdown_requested, "Flag should remain True after second signal")

            # Verify both signals were logged
            self.assertEqual(mock_logger.info.call_count, 2, "Both signals should be logged")

    @patch('runner.logger')
    def test_unknown_signal_number_handled(self, mock_logger):
        """Test that unknown signal numbers are handled gracefully"""
        handler = runner.SignalHandler()

        with handler:
            # Use an arbitrary signal number that may not have a name
            handler._handler(999, None)

            self.assertTrue(handler.shutdown_requested, "Flag should be set even for unknown signals")

            mock_logger.info.assert_called_once()

            # Should log the numeric value as string
            args, _ = mock_logger.info.call_args
            self.assertIn("999", args[0])

    def test_nested_context_managers(self):
        """Test that nested SignalHandler instances work correctly"""
        handler1 = runner.SignalHandler()
        handler2 = runner.SignalHandler()

        with handler1:
            sigint_after_first = signal.getsignal(signal.SIGINT)

            with handler2:
                sigint_after_second = signal.getsignal(signal.SIGINT)
                # Second handler should have installed its own handler
                self.assertNotEqual(sigint_after_second, sigint_after_first)

            # After exiting second context, first handler should be restored
            sigint_after_second_exit = signal.getsignal(signal.SIGINT)
            self.assertEqual(sigint_after_second_exit, sigint_after_first)

        # After exiting first context, original should be restored
        final_sigint = signal.getsignal(signal.SIGINT)
        self.assertEqual(final_sigint, self.original_sigint)

    def test_exception_in_context_still_restores_handlers(self):
        """Test that handlers are restored even if exception occurs in context"""
        handler = runner.SignalHandler()

        try:
            with handler:
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Verify handlers are restored despite exception
        restored_sigint = signal.getsignal(signal.SIGINT)
        restored_sigterm = signal.getsignal(signal.SIGTERM)

        self.assertEqual(restored_sigint, self.original_sigint, "SIGINT should be restored after exception")
        self.assertEqual(restored_sigterm, self.original_sigterm, "SIGTERM should be restored after exception")

    def test_shutdown_flag_persistence_after_exit(self):
        """Test that shutdown_requested flag persists after exiting context"""
        handler = runner.SignalHandler()

        with handler:
            handler._handler(signal.SIGINT, None)
            self.assertTrue(handler.shutdown_requested)

        # Flag should remain True after exiting context
        self.assertTrue(handler.shutdown_requested, "Flag should persist after context exit")

    @patch('runner.logger')
    def test_real_signal_delivery(self, mock_logger):
        """Test that actual signals are delivered and handled correctly"""
        import os
        import time

        handler = runner.SignalHandler()

        with handler:
            self.assertFalse(handler.shutdown_requested, "Flag should be False initially")

            # Send actual SIGINT to self (safe in test environment)
            # Note: This simulates what happens in production
            os.kill(os.getpid(), signal.SIGINT)

            # Give signal time to be delivered and processed
            time.sleep(0.1)

            # Verify flag was set
            self.assertTrue(handler.shutdown_requested, "Flag should be True after real signal delivery")
            mock_logger.info.assert_called()

class TestSignalHandlerIntegration(unittest.TestCase):
    """
    Integration tests simulating real-world SignalHandler usage patterns.
    """

    @patch('runner.logger')
    def test_typical_run_loop_pattern(self, _):
        """Test SignalHandler in a typical run loop pattern"""
        handler = runner.SignalHandler()
        iteration_count = 0

        with handler:
            # Simulate run loop
            while not handler.shutdown_requested:
                iteration_count += 1

                # Simulate work
                if iteration_count == 3:
                    # Simulate signal arrival
                    handler._handler(signal.SIGINT, None)

                # Check again after "subprocess"
                if handler.shutdown_requested:
                    break

                if iteration_count > 10:
                    self.fail("Loop should have exited after signal")

        # Verify loop executed expected number of times
        self.assertEqual(iteration_count, 3, "Loop should exit on iteration 3")
        self.assertTrue(handler.shutdown_requested, "Shutdown flag should be set")

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
