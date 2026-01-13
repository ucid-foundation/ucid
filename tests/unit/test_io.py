"""Unit tests for IO."""

from ucid.io import csv


def test_csv_write(tmp_path):
    f = tmp_path / "test.csv"
    csv.write_csv([{"a": 1}], str(f))
    assert f.exists()
