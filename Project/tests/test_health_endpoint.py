from fastapi.testclient import TestClient

from app import app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_endpoint_shape() -> None:
    client = TestClient(app)
    response = client.get("/metrics")

    assert response.status_code == 200
    body = response.json()
    assert "counters" in body
    assert isinstance(body["counters"], dict)
