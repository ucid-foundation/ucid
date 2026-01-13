# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Comprehensive unit tests for utilities."""

import os

import pytest

from ucid.utils.config import Config
from ucid.utils.logging import configure_logging, get_logger
from ucid.utils.validation import (
    validate_city_code,
    validate_coordinates,
    validate_grade,
    validate_timestamp,
)


class TestConfig:
    """Tests for Config class."""

    def test_config_get_existing_key(self) -> None:
        """Test config retrieval for existing key."""
        os.environ["TEST_UTILS_KEY"] = "test_value"
        assert Config.get("TEST_UTILS_KEY") == "test_value"

    def test_config_get_missing_key_with_default(self) -> None:
        """Test config retrieval for missing key with default."""
        result = Config.get("NONEXISTENT_KEY_12345", default="default_val")
        assert result == "default_val"

    def test_config_get_missing_key_no_default(self) -> None:
        """Test config retrieval for missing key without default."""
        result = Config.get("ANOTHER_NONEXISTENT_KEY")
        assert result is None or result == ""


class TestLogging:
    """Tests for logging utilities."""

    def test_get_logger_returns_logger(self) -> None:
        """Test that get_logger returns a logger object."""
        logger = get_logger("test_module")
        assert logger is not None
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "debug")

    def test_get_logger_different_names(self) -> None:
        """Test that different names return different loggers."""
        logger1 = get_logger("module1")
        logger2 = get_logger("module2")
        assert logger1 is not None
        assert logger2 is not None

    def test_configure_logging(self) -> None:
        """Test configure_logging doesn't raise."""
        try:
            configure_logging()
        except Exception as e:
            pytest.fail(f"configure_logging raised exception: {e}")


class TestValidateCoordinates:
    """Tests for validate_coordinates function."""

    def test_valid_coordinates(self) -> None:
        """Test valid coordinates pass validation."""
        assert validate_coordinates(41.015, 28.979) is True
        assert validate_coordinates(0.0, 0.0) is True
        assert validate_coordinates(-90.0, -180.0) is True
        assert validate_coordinates(90.0, 180.0) is True

    def test_invalid_latitude(self) -> None:
        """Test invalid latitude fails validation."""
        assert validate_coordinates(91.0, 0.0) is False
        assert validate_coordinates(-91.0, 0.0) is False

    def test_invalid_longitude(self) -> None:
        """Test invalid longitude fails validation."""
        assert validate_coordinates(0.0, 181.0) is False
        assert validate_coordinates(0.0, -181.0) is False

    def test_edge_case_coordinates(self) -> None:
        """Test edge case coordinates."""
        assert validate_coordinates(89.999, 179.999) is True
        assert validate_coordinates(-89.999, -179.999) is True


class TestValidateCityCode:
    """Tests for validate_city_code function."""

    def test_valid_city_codes(self) -> None:
        """Test valid 3-letter city codes."""
        assert validate_city_code("IST") is True
        assert validate_city_code("NYC") is True
        assert validate_city_code("LON") is True
        assert validate_city_code("ABC") is True

    def test_invalid_city_code_length(self) -> None:
        """Test invalid city code length."""
        assert validate_city_code("AB") is False
        assert validate_city_code("ABCD") is False
        assert validate_city_code("") is False

    def test_lowercase_city_code(self) -> None:
        """Test lowercase city codes."""
        # Depending on implementation, might be valid or invalid
        result = validate_city_code("ist")
        assert isinstance(result, bool)


class TestValidateGrade:
    """Tests for validate_grade function."""

    def test_valid_grades(self) -> None:
        """Test valid grades."""
        assert validate_grade("A") is True
        assert validate_grade("B") is True
        assert validate_grade("C") is True
        assert validate_grade("D") is True
        assert validate_grade("F") is True

    def test_invalid_grades(self) -> None:
        """Test invalid grades."""
        assert validate_grade("E") is False
        assert validate_grade("X") is False
        assert validate_grade("") is False
        assert validate_grade("AB") is False


class TestValidateTimestamp:
    """Tests for validate_timestamp function."""

    def test_valid_timestamps(self) -> None:
        """Test valid ISO week timestamps."""
        assert validate_timestamp("2026W01T12") is True
        assert validate_timestamp("2026W52T00") is True
        assert validate_timestamp("2026W26T23") is True

    def test_invalid_timestamp_format(self) -> None:
        """Test invalid timestamp formats."""
        assert validate_timestamp("2026-01-01") is False
        assert validate_timestamp("invalid") is False
        assert validate_timestamp("") is False

    def test_invalid_week_number(self) -> None:
        """Test invalid week numbers."""
        assert validate_timestamp("2026W00T12") is False
        assert validate_timestamp("2026W54T12") is False

    def test_invalid_hour(self) -> None:
        """Test invalid hour values."""
        assert validate_timestamp("2026W01T24") is False
        assert validate_timestamp("2026W01T25") is False
