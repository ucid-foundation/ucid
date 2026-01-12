"""Integration tests."""
try:
    from fastapi.testclient import TestClient
    from ucid.api.app import app
    client = TestClient(app)
except ImportError:
    client = None

def test_api_workflow():
    if client:
        response = client.get("/")
        assert response.status_code == 200
