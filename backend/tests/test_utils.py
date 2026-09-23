"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import tempfile
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp
from utils.file_handler import process_yaml_file


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessYamlFile(unittest.TestCase):
    """Tests for process_yaml_file ensuring safe YAML deserialization (CVE-2017-18342)"""

    def _write_yaml(self, content):
        """Helper: write content to a temp YAML file and return its path."""
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def tearDown(self):
        # Temp files are cleaned up individually in each test via addCleanup
        pass

    def test_parses_simple_mapping(self):
        """process_yaml_file should return a plain dict for a simple mapping."""
        path = self._write_yaml('name: Alice\nage: 30\n')
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result['name'], 'Alice')
        self.assertEqual(result['age'], 30)

    def test_parses_list(self):
        """process_yaml_file should return a list for a YAML sequence."""
        path = self._write_yaml('- alpha\n- beta\n- gamma\n')
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        self.assertIsInstance(result, list)
        self.assertEqual(result, ['alpha', 'beta', 'gamma'])

    def test_parses_nested_structure(self):
        """process_yaml_file should handle nested mappings."""
        path = self._write_yaml(
            'project:\n  name: hub\n  version: 1\nitems:\n  - a\n  - b\n'
        )
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        self.assertEqual(result['project']['name'], 'hub')
        self.assertEqual(result['items'], ['a', 'b'])

    def test_returns_none_for_empty_file(self):
        """process_yaml_file should return None for an empty YAML document."""
        path = self._write_yaml('')
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        self.assertIsNone(result)

    def test_returns_error_for_missing_file(self):
        """process_yaml_file should return an error dict when file is absent."""
        result = process_yaml_file('/nonexistent/path/does_not_exist.yaml')
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_safe_load_rejects_python_object_tags(self):
        """
        safe_load must NOT instantiate arbitrary Python objects.

        With the old yaml.load() (without a Loader), the !!python/object tag
        would deserialise into a real Python object, enabling arbitrary code
        execution (CVE-2017-18342).  yaml.safe_load() must raise an error
        instead of silently constructing the object.
        """
        # Craft YAML that would execute code with the unsafe yaml.load() call
        malicious_yaml = (
            '!!python/object/apply:os.system\n'
            "args: ['echo CVE-2017-18342-exploit']\n"
        )
        path = self._write_yaml(malicious_yaml)
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        # safe_load raises yaml.YAMLError; process_yaml_file catches it and
        # returns {'error': <message>} rather than executing the payload.
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)
        # The result must NOT be a truthy non-dict (i.e. must not have executed)
        self.assertNotIsInstance(result, int)

    def test_safe_load_rejects_object_new_tag(self):
        """
        Another common unsafe tag (!!python/object/new) must be rejected.
        """
        path = self._write_yaml(
            '!!python/object/new:subprocess.Popen\n'
            "args: [['id']]\n"
        )
        self.addCleanup(os.unlink, path)
        result = process_yaml_file(path)
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()

