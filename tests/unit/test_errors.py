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

"""Comprehensive unit tests for UCID errors."""

import pytest

from ucid.core.errors import (
    UCIDConfigError,
    UCIDContextError,
    UCIDDataError,
    UCIDError,
    UCIDParseError,
    UCIDRegistryError,
    UCIDValidationError,
)


class TestUCIDError:
    """Tests for base UCIDError."""

    def test_ucid_error_basic(self) -> None:
        """Test basic UCIDError creation."""
        error = UCIDError("Test error message")
        assert error.message == "Test error message"
        assert error.error_code == "INTERNAL_ERROR"
        assert error.details == {}

    def test_ucid_error_with_details(self) -> None:
        """Test UCIDError with details."""
        error = UCIDError(
            "Error with details",
            details={"field": "city", "value": "invalid"},
        )
        assert error.details["field"] == "city"
        assert error.details["value"] == "invalid"

    def test_ucid_error_with_custom_code(self) -> None:
        """Test UCIDError with custom code."""
        error = UCIDError("Custom error", code="CUSTOM_CODE")
        assert error.error_code == "CUSTOM_CODE"

    def test_ucid_error_repr(self) -> None:
        """Test UCIDError __repr__."""
        error = UCIDError("Test message", code="TEST_CODE")
        repr_str = repr(error)
        assert "UCIDError" in repr_str
        assert "TEST_CODE" in repr_str
        assert "Test message" in repr_str

    def test_ucid_error_is_exception(self) -> None:
        """Test that UCIDError is an Exception."""
        error = UCIDError("Test")
        assert isinstance(error, Exception)

    def test_ucid_error_str(self) -> None:
        """Test UCIDError str conversion."""
        error = UCIDError("Error string test")
        assert str(error) == "Error string test"


class TestUCIDParseError:
    """Tests for UCIDParseError."""

    def test_parse_error_basic(self) -> None:
        """Test basic UCIDParseError."""
        error = UCIDParseError("Invalid format")
        assert error.error_code == "PARSE_ERROR"
        assert "Invalid format" in error.message

    def test_parse_error_inheritance(self) -> None:
        """Test UCIDParseError inherits from UCIDError."""
        error = UCIDParseError("Test")
        assert isinstance(error, UCIDError)

    def test_parse_error_with_details(self) -> None:
        """Test UCIDParseError with details."""
        error = UCIDParseError(
            "Field format error",
            details={"field_index": 3, "expected": "float"},
        )
        assert error.details["field_index"] == 3

    def test_parse_error_raise_and_catch(self) -> None:
        """Test raising and catching UCIDParseError."""
        with pytest.raises(UCIDParseError) as exc_info:
            raise UCIDParseError("Test parse error")
        assert "Test parse error" in str(exc_info.value)


class TestUCIDValidationError:
    """Tests for UCIDValidationError."""

    def test_validation_error_basic(self) -> None:
        """Test basic UCIDValidationError."""
        error = UCIDValidationError("Invalid city code")
        assert error.error_code == "VALIDATION_ERROR"

    def test_validation_error_inheritance(self) -> None:
        """Test UCIDValidationError inherits from UCIDError."""
        error = UCIDValidationError("Test")
        assert isinstance(error, UCIDError)


class TestUCIDContextError:
    """Tests for UCIDContextError."""

    def test_context_error_basic(self) -> None:
        """Test basic UCIDContextError."""
        error = UCIDContextError("Context computation failed")
        assert error.error_code == "CONTEXT_ERROR"

    def test_context_error_inheritance(self) -> None:
        """Test UCIDContextError inherits from UCIDError."""
        error = UCIDContextError("Test")
        assert isinstance(error, UCIDError)


class TestUCIDDataError:
    """Tests for UCIDDataError."""

    def test_data_error_basic(self) -> None:
        """Test basic UCIDDataError."""
        error = UCIDDataError("Missing OSM data")
        assert error.error_code == "DATA_ERROR"

    def test_data_error_inheritance(self) -> None:
        """Test UCIDDataError inherits from UCIDError."""
        error = UCIDDataError("Test")
        assert isinstance(error, UCIDError)


class TestUCIDConfigError:
    """Tests for UCIDConfigError."""

    def test_config_error_basic(self) -> None:
        """Test basic UCIDConfigError."""
        error = UCIDConfigError("Invalid config schema")
        assert error.error_code == "CONFIG_ERROR"

    def test_config_error_inheritance(self) -> None:
        """Test UCIDConfigError inherits from UCIDError."""
        error = UCIDConfigError("Test")
        assert isinstance(error, UCIDError)


class TestUCIDRegistryError:
    """Tests for UCIDRegistryError."""

    def test_registry_error_basic(self) -> None:
        """Test basic UCIDRegistryError."""
        error = UCIDRegistryError("City not found in registry")
        assert error.error_code == "REGISTRY_ERROR"

    def test_registry_error_inheritance(self) -> None:
        """Test UCIDRegistryError inherits from UCIDError."""
        error = UCIDRegistryError("Test")
        assert isinstance(error, UCIDError)


class TestErrorHierarchy:
    """Tests for error hierarchy."""

    def test_catch_all_errors_with_base(self) -> None:
        """Test catching all UCID errors with base class."""
        errors = [
            UCIDParseError("parse"),
            UCIDValidationError("validation"),
            UCIDContextError("context"),
            UCIDDataError("data"),
            UCIDConfigError("config"),
            UCIDRegistryError("registry"),
        ]
        for error in errors:
            try:
                raise error
            except UCIDError as e:
                assert isinstance(e, UCIDError)

    def test_error_codes_are_distinct(self) -> None:
        """Test that all error classes have distinct error codes."""
        codes = [
            UCIDParseError("").error_code,
            UCIDValidationError("").error_code,
            UCIDContextError("").error_code,
            UCIDDataError("").error_code,
            UCIDConfigError("").error_code,
            UCIDRegistryError("").error_code,
        ]
        assert len(codes) == len(set(codes))
