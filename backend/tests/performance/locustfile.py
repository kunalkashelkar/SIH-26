"""
Locust load test suite for Cypher Web Application Fuzzer API.
Tests dashboard metrics aggregation, scan history retrieval, findings queries,
and scan detail retrieval under concurrent simulated load.
Run via:
    locust -f tests/performance/locustfile.py --host=http://localhost:8000
"""
from locust import HttpUser, task, between

class CypherApiUser(HttpUser):
    wait_time = between(0.5, 2.0)

    @task(4)
    def test_dashboard_metrics(self):
        """Simulate frequent dashboard metrics polling."""
        self.client.get("/api/scans/metrics/dashboard", name="/api/scans/metrics/dashboard")

    @task(3)
    def test_list_scans(self):
        """Simulate loading scans list."""
        self.client.get("/api/scans?limit=20", name="/api/scans")

    @task(2)
    def test_list_findings(self):
        """Simulate loading findings list with filtering."""
        self.client.get("/api/findings?limit=20", name="/api/findings")

    @task(1)
    def test_health_check(self):
        """Liveness / health check endpoint."""
        self.client.get("/api/health", name="/api/health")
