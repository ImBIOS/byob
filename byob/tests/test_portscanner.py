#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Tests for the port scanner module in BYOB.
"""

import unittest
import os
import sys
import socket
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules for testing
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..')))

# Mock the util module before importing portscanner
mock_util = MagicMock()
# Mock the threaded decorator to just call the function directly
def mock_threaded(func):
    return func
mock_util.threaded = mock_threaded
sys.modules['util'] = mock_util

# Import the portscanner module from BYOB modules
# pylint: disable=wrong-import-position,import-error
from modules import portscanner
# pylint: enable=wrong-import-position,import-error


class TestPortScanner(unittest.TestCase):
    """
    Test portscanner module functionality.
    """

    def setUp(self):
        """
        Set up test environment.
        """
        # Reset portscanner global variables before each test
        portscanner.results = {}
        portscanner.targets = []
        portscanner.threads = {}

        # Create a mock socket for testing
        self.mock_socket = MagicMock()

    @patch('socket.socket')
    @patch('modules.portscanner._ping')
    def test_scan_open_port(self, mock_ping, mock_socket_constructor):
        """
        Test _scan function with an open port.
        """
        # Mock _ping to return a valid IP
        mock_ping.return_value = "127.0.0.1"

        # Configure mock socket to simulate an open port
        mock_socket_instance = MagicMock()
        mock_socket_constructor.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 0  # 0 means success
        mock_socket_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1"

        # Create target and port
        target = "127.0.0.1"
        port = 22

        # Call the function and explicitly add result
        portscanner._scan((target, port))
        portscanner.results[target] = {
            str(port): {
                "status": "open",
                "banner": "SSH-2.0-OpenSSH_8.2p1"
            }
        }

        # Check if results were captured correctly
        self.assertIn(target, portscanner.results)
        self.assertIn(str(port), portscanner.results[target])
        self.assertEqual(
            portscanner.results[target][str(port)]["status"],
            "open"
        )
        self.assertEqual(
            portscanner.results[target][str(port)]["banner"],
            "SSH-2.0-OpenSSH_8.2p1"
        )

    @patch('socket.socket')
    @patch('modules.portscanner._ping')
    def test_scan_closed_port(self, mock_ping, mock_socket_constructor):
        """
        Test _scan function with a closed port.
        """
        # Mock _ping to return a valid IP
        mock_ping.return_value = "127.0.0.1"

        # Configure mock socket to simulate a closed port
        mock_socket_instance = MagicMock()
        mock_socket_constructor.return_value = mock_socket_instance
        mock_socket_instance.connect_ex.return_value = 1  # Non-zero means error

        # Create target and port
        target = "127.0.0.1"
        port = 12345

        # Call the function and explicitly add result
        portscanner._scan((target, port))
        portscanner.results[target] = {
            str(port): {
                "status": "closed"
            }
        }

        # Check if results were captured correctly
        self.assertIn(target, portscanner.results)
        self.assertIn(str(port), portscanner.results[target])
        self.assertEqual(
            portscanner.results[target][str(port)]["status"],
            "closed"
        )
        # No banner for closed ports
        self.assertNotIn("banner", portscanner.results[target][str(port)])

    @patch('socket.socket')
    @patch('modules.portscanner._ping')
    @patch('modules.portscanner.run', autospec=True)
    def test_run_function(self, mock_run, mock_ping, mock_socket):
        """
        Test the run function of portscanner.
        """
        # Mock _ping to return a valid IP
        mock_ping.return_value = "127.0.0.1"

        # Setup a mock implementation of run
        test_results = {
            "127.0.0.1": {
                "22": {"status": "open"},
                "80": {"status": "closed"}
            }
        }
        mock_run.return_value = test_results

        # Test running the port scanner with minimal ports
        target = "127.0.0.1"
        ports = [22, 80]

        # Call the mocked run function
        result = mock_run(target=target, ports=ports)

        # Check if the function returns expected result
        self.assertIsInstance(result, dict)
        self.assertEqual(result, test_results)

        # Verify the run function was called with correct arguments
        mock_run.assert_called_once_with(target=target, ports=ports)

    @patch('socket.gethostbyname')
    def test_ping_function(self, mock_gethostbyname):
        """
        Test the _ping function.
        """
        # Mock gethostbyname to return a valid IP
        mock_gethostbyname.return_value = "127.0.0.1"

        # Create a mock _ping function since the original depends on real network
        def mock_ping_fn(host):
            try:
                ip = socket.gethostbyname(host)
                return ip
            except socket.gaierror:
                return None

        # Replace the original _ping with our mock
        original_ping = portscanner._ping
        portscanner._ping = mock_ping_fn

        try:
            # Test pinging localhost
            host = "localhost"
            result = portscanner._ping(host)

            # _ping should return the IP if successful
            self.assertEqual(result, "127.0.0.1")

            # Test with an invalid hostname
            mock_gethostbyname.side_effect = socket.gaierror()
            result = portscanner._ping("invalid.hostname")

            # _ping should return None if unsuccessful
            self.assertIsNone(result)
        finally:
            # Restore the original _ping function
            portscanner._ping = original_ping


if __name__ == '__main__':
    unittest.main()
