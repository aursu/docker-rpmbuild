#!/usr/bin/env python3

import errno
import sys
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner

class TestFileSystemVerification(unittest.TestCase):
    """
    Tests for FileSystemManager.verify_binary_permissions
    """

    def setUp(self):
        # self.config = MagicMock()
        # # Mocking the path object inside config
        # self.config.listener_bin = MagicMock(spec=Path)
        # self.config.listener_bin.__str__.return_value = "/usr/local/runner/bin/Runner.Listener"
        self.config = runner.Config()

        self.fman = runner.FileSystemManager(self.config)

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.chmod')
    def test_verify_binary_exists_and_executable(self, mock_chmod, mock_exists):
        """Case 1: File exists and is already executable (Do nothing)"""
        mock_exists.return_value = True

        with patch('os.access', return_value=True) as mock_access:
            self.fman.verify_binary_permissions()

            # Should check X_OK
            mock_access.assert_called_once_with(self.config.listener_bin, runner.os.X_OK)
            # Should NOT try to chmod
            mock_chmod.assert_not_called()

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.stat')
    @patch('pathlib.Path.chmod')
    def test_verify_binary_fixes_permissions(self, mock_chmod, mock_stat, mock_exists):
        """Case 2: File exists but not executable (Apply chmod +x)"""
        mock_exists.return_value = True

        # Mock os.access to return False (not executable)
        with patch('os.access', return_value=False):
            # Mock stat() to return some current mode (e.g., 644 - rw-r--r--)
            stat_obj = MagicMock()
            stat_obj.st_mode = 0o644

            mock_stat.return_value = stat_obj

            self.fman.verify_binary_permissions()

            # Should call chmod with 0o644 | 0o111 = 0o755 (rwxr-xr-x)
            expected_mode = 0o644 | 0o111
            mock_chmod.assert_called_once_with(expected_mode)

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.stat')
    @patch('pathlib.Path.chmod')
    def test_verify_binary_chmod_fails(self, mock_chmod, mock_stat, mock_exists):
        """Case 3: File not executable and chmod fails (Raise Error)"""
        mock_exists.return_value = True
        expected_path = str(self.config.listener_bin)

        with patch('os.access', return_value=False):
            stat_obj = MagicMock()
            stat_obj.st_mode = 0o644

            mock_stat.return_value = stat_obj

            # Simulate permission denied during chmod
            mock_chmod.side_effect = PermissionError(errno.EPERM, "Operation not permitted", expected_path)

            with self.assertRaises(runner.RunnerError) as cm:
                self.fman.verify_binary_permissions()

            self.assertIn("Failed to set executable permissions", str(cm.exception))
            self.assertIn(expected_path, str(cm.exception))
            self.assertIn("Operation not permitted", str(cm.exception))

    @patch('pathlib.Path.exists')
    def test_verify_binary_missing(self, mock_exists):
        """Case 4: Binary file does not exist (Raise Error)"""
        mock_exists.return_value = False

        with self.assertRaises(runner.RunnerError) as cm:
            self.fman.verify_binary_permissions()

        self.assertIn("Runner binary not found", str(cm.exception))

if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)