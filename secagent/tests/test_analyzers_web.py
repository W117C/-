"""Tests for analyzers: traffic_analyzer, web_scraper."""
from __future__ import annotations

from secagent.analyzers.traffic_analyzer import (
    HTTPEntry,
    analyze_traffic_flow,
    parse_har,
)
from secagent.analyzers.web_scraper import (
    RequestInterceptor,
    ScraperConfig,
    SessionManager,
    generate_mouse_trace,
    generate_typing_delay,
)

_SAMPLE_HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/users",
                    "headers": [{"name": "Accept", "value": "application/json"}],
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "content": {"mimeType": "application/json", "text": "{}"},
                },
                "time": 150,
            },
            {
                "request": {
                    "method": "POST",
                    "url": "https://api.example.com/login",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                },
                "response": {
                    "status": 302,
                    "headers": [
                        {"name": "Location", "value": "/dashboard"},
                        {"name": "Set-Cookie", "value": "session=abc"},
                    ],
                    "content": {"mimeType": "text/html", "text": ""},
                },
                "time": 200,
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://static.example.com/app.js",
                    "headers": [],
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Content-Type", "value": "application/javascript"}],
                    "content": {"mimeType": "application/javascript", "text": "var x = 1;"},
                },
                "time": 50,
            },
        ]
    }
}


# ======================================================================
# traffic_analyzer
# ======================================================================

class TestTrafficAnalyzer:

    def test_parse_har_returns_entries(self):
        entries = parse_har(_SAMPLE_HAR)
        assert len(entries) == 3

    def test_parse_har_entry_fields(self):
        entries = parse_har(_SAMPLE_HAR)
        e = entries[0]
        assert e.method == "GET"
        assert e.url == "https://api.example.com/users"
        assert e.status_code == 200
        assert e.duration_ms == 150.0

    def test_parse_har_headers(self):
        entries = parse_har(_SAMPLE_HAR)
        assert entries[0].request_headers.get("Accept") == "application/json"
        assert entries[0].response_headers.get("Content-Type") == "application/json"

    def test_parse_har_empty_log(self):
        assert parse_har({"log": {"entries": []}}) == []

    def test_parse_har_invalid(self):
        assert parse_har({}) == []

    def test_analyze_traffic_flow_api(self):
        entries = parse_har(_SAMPLE_HAR)
        chain = analyze_traffic_flow(entries)
        # /users and /login have JSON or XML content type → API
        assert len(chain.api_calls) >= 1

    def test_analyze_traffic_flow_static(self):
        entries = parse_har(_SAMPLE_HAR)
        chain = analyze_traffic_flow(entries)
        assert len(chain.static_assets) == 1  # app.js

    def test_analyze_traffic_flow_redirect(self):
        entries = parse_har(_SAMPLE_HAR)
        chain = analyze_traffic_flow(entries)
        assert len(chain.redirects) == 1  # 302

    def test_analyze_traffic_flow_empty(self):
        chain = analyze_traffic_flow([])
        assert len(chain.entries) == 0
        assert len(chain.api_calls) == 0


# ======================================================================
# web_scraper
# ======================================================================

class TestWebScraper:

    def test_scraper_config_defaults(self):
        cfg = ScraperConfig()
        assert cfg.headless is True
        assert cfg.viewport == (1920, 1080)

    def test_scraper_config_custom(self):
        cfg = ScraperConfig(headless=False, timeout=60000, block_images=True)
        assert cfg.headless is False
        assert cfg.timeout == 60000
        assert cfg.block_images is True

    def test_request_interceptor_init(self):
        it = RequestInterceptor()
        assert len(it.get_captured()) == 0

    def test_request_interceptor_block_rule(self):
        it = RequestInterceptor()
        it.add_block_rule(r"\.jpg$")
        it.add_block_rule(r"\.png$")
        assert len(it._route_rules) == 2

    def test_request_interceptor_abort_rule(self):
        it = RequestInterceptor()
        it.add_abort_rule("image")
        it.add_abort_rule("font")
        assert len(it._route_rules) == 2

    def test_request_interceptor_clear(self):
        it = RequestInterceptor()
        it._captured_requests.append({"url": "https://x.com"})
        assert len(it.get_captured()) == 1
        it.clear()
        assert len(it.get_captured()) == 0

    def test_generate_mouse_trace_length(self):
        trace = generate_mouse_trace(0, 0, 100, 100, steps=5)
        assert len(trace) == 6  # steps + 1

    def test_generate_mouse_trace_fields(self):
        trace = generate_mouse_trace(0, 0, 100, 100, steps=3)
        for point in trace:
            assert "x" in point
            assert "y" in point
            assert "timestamp" in point

    def test_generate_mouse_trace_endpoint(self):
        """Trace should end near the target coordinates."""
        trace = generate_mouse_trace(0, 0, 100, 200, steps=10)
        last = trace[-1]
        assert abs(last["x"] - 100) < 5
        assert abs(last["y"] - 200) < 5

    def test_generate_typing_delay_length(self):
        delays = generate_typing_delay("Hello")
        assert len(delays) == 5

    def test_generate_typing_delay_values(self):
        delays = generate_typing_delay("Hi!")
        for d in delays:
            assert 0.03 <= d <= 1.0  # within expected range

    def test_generate_typing_delay_empty(self):
        assert generate_typing_delay("") == []

    def test_session_manager_default_path(self):
        sm = SessionManager()
        assert sm._storage_file.endswith("scraper_storage.json")
