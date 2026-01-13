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

"""Comprehensive unit tests for temporal module."""

from ucid.temporal import TemporalAnalyzer


class TestTemporalAnalyzerDecompose:
    """Tests for TemporalAnalyzer.decompose method."""

    def test_decompose_basic(self) -> None:
        """Test basic decomposition."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 75.0, 80.0, 85.0]
        result = analyzer.decompose(timeseries, freq=4)
        assert "trend" in result
        assert "seasonal" in result
        assert "residual" in result

    def test_decompose_returns_correct_length(self) -> None:
        """Test that decomposition returns correct length arrays."""
        analyzer = TemporalAnalyzer()
        timeseries = [1.0, 2.0, 3.0, 4.0, 5.0]
        result = analyzer.decompose(timeseries, freq=2)
        assert len(result["trend"]) == len(timeseries)
        assert len(result["seasonal"]) == len(timeseries)
        assert len(result["residual"]) == len(timeseries)

    def test_decompose_empty_series(self) -> None:
        """Test decomposition with empty series."""
        analyzer = TemporalAnalyzer()
        result = analyzer.decompose([], freq=4)
        assert result["trend"] == []
        assert result["seasonal"] == []
        assert result["residual"] == []


class TestTemporalAnalyzerDetectAnomalies:
    """Tests for TemporalAnalyzer.detect_anomalies method."""

    def test_detect_anomalies_no_anomalies(self) -> None:
        """Test detection with no anomalies."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 71.0, 72.0, 73.0, 74.0]
        result = analyzer.detect_anomalies(timeseries)
        assert len(result) == 0

    def test_detect_anomalies_with_outlier(self) -> None:
        """Test detection with clear outlier."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 71.0, 72.0, 73.0, 150.0]  # 150 is outlier
        result = analyzer.detect_anomalies(timeseries, threshold=2.0)
        assert 4 in result  # Index 4 should be detected

    def test_detect_anomalies_short_series(self) -> None:
        """Test detection with short series."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 71.0]  # Less than 3 elements
        result = analyzer.detect_anomalies(timeseries)
        assert result == []

    def test_detect_anomalies_constant_series(self) -> None:
        """Test detection with constant series."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 70.0, 70.0, 70.0]
        result = analyzer.detect_anomalies(timeseries)
        assert result == []  # std = 0, no anomalies

    def test_detect_anomalies_custom_threshold(self) -> None:
        """Test detection with custom threshold."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 72.0, 74.0, 100.0]
        result_high = analyzer.detect_anomalies(timeseries, threshold=3.0)
        result_low = analyzer.detect_anomalies(timeseries, threshold=1.0)
        # Low threshold should detect more anomalies
        assert len(result_low) >= len(result_high)


class TestTemporalAnalyzerForecast:
    """Tests for TemporalAnalyzer.forecast method."""

    def test_forecast_basic(self) -> None:
        """Test basic forecasting."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 75.0, 80.0, 85.0]
        result = analyzer.forecast(timeseries, periods=3)
        assert len(result) == 3

    def test_forecast_returns_last_value(self) -> None:
        """Test that forecast returns last value (naive forecast)."""
        analyzer = TemporalAnalyzer()
        timeseries = [70.0, 75.0, 80.0, 85.0]
        result = analyzer.forecast(timeseries, periods=2)
        assert all(v == 85.0 for v in result)

    def test_forecast_empty_series(self) -> None:
        """Test forecast with empty series."""
        analyzer = TemporalAnalyzer()
        result = analyzer.forecast([], periods=5)
        assert len(result) == 5
        assert all(v == 0.0 for v in result)

    def test_forecast_single_value(self) -> None:
        """Test forecast with single value."""
        analyzer = TemporalAnalyzer()
        result = analyzer.forecast([100.0], periods=3)
        assert len(result) == 3
        assert all(v == 100.0 for v in result)


class TestTemporalAnalyzerInstantiation:
    """Tests for TemporalAnalyzer instantiation."""

    def test_create_analyzer(self) -> None:
        """Test creating analyzer instance."""
        analyzer = TemporalAnalyzer()
        assert analyzer is not None

    def test_analyzer_has_methods(self) -> None:
        """Test analyzer has expected methods."""
        analyzer = TemporalAnalyzer()
        assert hasattr(analyzer, "decompose")
        assert hasattr(analyzer, "detect_anomalies")
        assert hasattr(analyzer, "forecast")
