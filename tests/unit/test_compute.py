"""Unit tests for compute."""
from ucid.compute.chunking import chunk_list
from ucid.compute.backpressure import RateLimiter
import time

def test_chunking():
    chunks = list(chunk_list([1, 2, 3, 4], 2))
    assert len(chunks) == 2
    assert chunks[0] == [1, 2]

def test_backpressure():
    rl = RateLimiter(100)
    rl.acquire() # Should return immediately
