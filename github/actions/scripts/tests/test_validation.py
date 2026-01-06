#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import runner

class TestConfigValidation(unittest.TestCase):
    """
    Tests for Input Validation and Sanitization in Config.
    """

    def setUp(self):
        # Базовый набор валидных переменных
        self.base_env = {
            'GITHUB_URL': 'https://github.com/org/repo',
            'GITHUB_TOKEN': 'ghp_validtoken123',
            'RUNNER_NAME': 'valid-runner-01'
        }

    def test_runner_name_valid(self):
        """Test standard valid names"""
        valid_names = [
            "my-runner",
            "runner_01",
            "prod.server.eu",
            "SimpleRunner"
        ]
        for name in valid_names:
            env = self.base_env.copy()
            env['RUNNER_NAME'] = name
            with patch.dict('os.environ', env, clear=True):
                config = runner.Config()
                # Should not raise exception
                try:
                    config.validate()
                except runner.RunnerError:
                    self.fail(f"Valid name '{name}' raised RunnerError unexpectedy")

    def test_runner_name_invalid_chars(self):
        """Test names with illegal characters fail validation"""
        invalid_names = [
            "runner with spaces",
            "runner;rm -rf /",  # Command injection attempt
            "runner&background",
            "runner$VAR",
            "/etc/runner"       # Path traversal attempt
        ]
        for name in invalid_names:
            env = self.base_env.copy()
            env['RUNNER_NAME'] = name
            with patch.dict('os.environ', env, clear=True):
                config = runner.Config()
                with self.assertRaises(runner.RunnerError) as cm:
                    config.validate()
                self.assertIn(f"Invalid RUNNER_NAME '{name}'", str(cm.exception))

    def test_labels_valid(self):
        """Test valid comma-separated labels"""
        env = self.base_env.copy()
        env['RUNNER_LABELS'] = "linux,x64,production,high-cpu"

        with patch.dict('os.environ', env, clear=True):
            config = runner.Config()
            # Should pass
            config.validate()

    def test_labels_invalid(self):
        """Test labels with invalid characters"""
        env = self.base_env.copy()
        # "good-label" is fine, but "bad label" has a space
        env['RUNNER_LABELS'] = "good-label,bad label,gpu"

        with patch.dict('os.environ', env, clear=True):
            config = runner.Config()
            with self.assertRaises(runner.RunnerError) as cm:
                config.validate()
            self.assertIn("Invalid label 'bad label'", str(cm.exception))

    def test_runner_group_invalid(self):
        """Test runner group validation"""
        env = self.base_env.copy()
        env['RUNNER_GROUP'] = "Default Group" # Has space

        with patch.dict('os.environ', env, clear=True):
            config = runner.Config()
            with self.assertRaises(runner.RunnerError) as cm:
                config.validate()
            self.assertIn("Invalid RUNNER_GROUP", str(cm.exception))

if __name__ == '__main__':
    unittest.main(verbosity=2)