"""Performance benchmarks."""
import pytest
import time
from ucid.core.parser import parse_ucid

def test_parse_benchmark(benchmark):
    valid = "UCID-V1:IST:41.015:28.979:9:891f2ed6df7ffff:2026W03T14:15MIN:A:0.95:"
    def _parse():
        parse_ucid(valid)
        
    benchmark(_parse)
