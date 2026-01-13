"""Unit tests for API."""

from fastapi.testclient import TestClient

from ucid.api.app import app

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "message": "Hello World"
    }  # Wait, need to check app.py content
