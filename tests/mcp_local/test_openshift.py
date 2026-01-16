"""Test the mcp_local.openshift module."""

import json
import os
import pathlib
import re
import subprocess
from unittest.mock import patch

import pytest
from langchain_mcp_adapters.client import MultiServerMCPClient

from mcp_local.openshift import (
    ALLOWED_ALERTMANAGER_ENDPOINTS,
    ALLOWED_PROMETHEUS_ENDPOINTS,
    BLOCKED_CHARS,
    BLOCKED_CHARS_DETECTED_MSG,
    MAX_QUERY_LENGTH,
    MAX_RESPONSE_SIZE,
    SECRET_NOT_ALLOWED_MSG,
    convert_relative_time,
    get_route_url,
    oc_adm_top,
    oc_api_get,
    oc_describe,
    oc_get,
    oc_logs,
    oc_query_alerts,
    oc_query_prometheus,
    oc_query_prometheus_range,
    oc_status,
    query_api_endpoint,
    raise_for_unacceptable_args,
    redact_token,
    run_oc,
    safe_run_oc,
    sanitize_query_params,
    show_pods_resource_usage,
    strip_args_for_oc_command,
    validate_alertmanager_endpoint,
    validate_prometheus_endpoint,
    validate_query_length,
)


@pytest.fixture(scope="function")
def token_in_env():
    """Set up a token in the environment for testing."""
    with patch.dict(
        os.environ,
        {"OC_USER_TOKEN": "fake-token"},
    ):
        yield


def test_strip_args_for_oc_command():
    """Test the strip_args_for_oc_command function."""
    # normal case
    args = ["pod", "my-pod"]
    expected = ["pod", "my-pod"]
    assert strip_args_for_oc_command(args) == expected

    # extra commands
    args = ["get", "pod", "my-pod"]
    expected = ["pod", "my-pod"]
    assert strip_args_for_oc_command(args) == expected

    # multiple extra commands
    args = ["oc", "get", "pod", "my-pod"]
    expected = ["pod", "my-pod"]
    assert strip_args_for_oc_command(args) == expected

    # extra spaces
    args = ["oc", " get ", " pod ", " my-pod "]
    expected = ["pod", "my-pod"]
    assert strip_args_for_oc_command(args) == expected

    # two commands as one
    args = ["pod my-pod"]
    expected = ["pod", "my-pod"]
    assert strip_args_for_oc_command(args) == expected

    # empty list
    args = []
    expected = []
    assert strip_args_for_oc_command(args) == expected


def test_raise_for_unacceptable_args():
    """Test the unacceptable args check."""
    # blocked character present
    for char in BLOCKED_CHARS:
        args = ["oc", "get", f"pod{char}my-pod"]
        with pytest.raises(Exception, match=re.escape(BLOCKED_CHARS_DETECTED_MSG)):
            raise_for_unacceptable_args(args)

    # secret/secrets present
    for s in ["secret", "secrets"]:
        args = ["oc", "get", s, "my-secret"]
        with pytest.raises(Exception, match=SECRET_NOT_ALLOWED_MSG):
            raise_for_unacceptable_args(args)

    # no blocked character, no error (returns nothing)
    assert raise_for_unacceptable_args(["oc", "get", "pod", "my-pod"]) is None

    # empty list, no error (returns nothing)
    assert raise_for_unacceptable_args([]) is None


def test_safe_run_oc():
    """Test the run_oc function."""
    # secret present
    with pytest.raises(Exception, match=SECRET_NOT_ALLOWED_MSG):
        safe_run_oc("get", ["secret"])

    # forbidden characters present
    with pytest.raises(Exception, match=re.escape(BLOCKED_CHARS_DETECTED_MSG)):
        safe_run_oc("get", ["pod", "my-pod;"])

    # normal case
    args = ["pod", "my-pod"]
    mocked_oc = "stdout"
    with patch("mcp_local.openshift.run_oc", return_value=mocked_oc):
        response = safe_run_oc("get", args)
        assert response == "stdout"


def test_token_default_value():
    """Test the default value of the token in the environment."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="stdout and fake-token",
            stderr="",
        )
        run_oc([])

        assert "token-not-set" in mock_run.call_args[0][0]


def test_oc_run(token_in_env):
    """Test the run_oc function."""
    args = ["pod", "my-pod"]
    expected_args = ["oc", *args, "--token", "fake-token"]

    # normal case - token is in response - should be redacted
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="stdout and fake-token",
            stderr="",
        )
        response = run_oc(args)

        # called with args and token
        assert expected_args == mock_run.call_args[0][0]

        assert response == "stdout and <redacted>"

    # error case
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr="stderr and fake-token",
        )
        with pytest.raises(Exception, match="stderr and <redacted>"):
            run_oc(args)

    # quasi case
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["oc", "get", "pod", "my-pod"],
            returncode=0,
            stdout="",
            stderr="stderr and fake-token",
        )
        response = run_oc(args)

        # called with args and token
        assert expected_args == mock_run.call_args[0][0]

        assert response == "stderr and <redacted>"

    # exception case
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.side_effect = Exception("error and fake-token")

        with pytest.raises(Exception) as exception:
            run_oc(args)
        assert "Traceback" in str(exception.value)
        assert "error and <redacted>" in str(exception.value)
        assert "fake-token" not in str(exception.value)


@pytest.mark.parametrize("tool", (oc_get, oc_describe, oc_logs, oc_status, oc_adm_top))
def test_tools(tool, token_in_env):
    """Test tools that take arguments."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        args = ["irelevant"]
        mock_run.return_value = subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="stdout",
            stderr="",
        )

        result = tool(args)
        assert result == "stdout"


def test_argless_tools(token_in_env):
    """Test tools that don't take any arguments."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="stdout",
            stderr="",
        )

        result = show_pods_resource_usage()
        assert result == "stdout"


@pytest.mark.asyncio
async def test_is_stdio_server():
    """Test if the server is a stdio server."""
    mcp_client = MultiServerMCPClient(
        {
            "math": {
                "command": "python",
                "args": [
                    (
                        pathlib.Path(__file__).parent.parent.parent
                        / "mcp_local/openshift.py"
                    ).as_posix()
                ],
                "transport": "stdio",
            },
        }
    )

    tools = await mcp_client.get_tools()
    assert len(tools) == 10
    assert tools[0].name == "oc_get"
    assert tools[1].name == "oc_describe"
    assert tools[2].name == "oc_logs"
    assert tools[3].name == "oc_status"
    assert tools[4].name == "show_pods_resource_usage"
    assert tools[5].name == "oc_adm_top"
    assert tools[6].name == "oc_query_prometheus"
    assert tools[7].name == "oc_query_prometheus_range"
    assert tools[8].name == "oc_query_alerts"
    assert tools[9].name == "oc_api_get"


def test_redact_token():
    """Test the redact_token function."""
    text = "texty text with token"
    token = "token"  # noqa: S105

    assert redact_token(text, token) == "texty text with <redacted>"


def test_redact_token_with_empty_token():
    """Test that redact_token returns text unchanged when token is empty."""
    text = "NAME STATUS AGE"

    # Empty string token should not modify text
    assert redact_token(text, "") == text

    # Default token value should not modify text
    assert redact_token(text, "token-not-set") == text


def test_get_route_url(token_in_env):
    """Test getting route URL."""
    with patch("mcp_local.openshift.run_oc") as mock_run:
        mock_run.return_value = "thanos-querier-openshift-monitoring.apps.cluster.com"
        url = get_route_url("thanos-querier")

        assert url == "https://thanos-querier-openshift-monitoring.apps.cluster.com"
        mock_run.assert_called_once_with([
            "get",
            "route",
            "thanos-querier",
            "-n",
            "openshift-monitoring",
            "-o",
            "jsonpath={.spec.host}",
        ])


def test_get_route_url_not_found(token_in_env):
    """Test getting route URL when route is not found."""
    with patch("mcp_local.openshift.run_oc") as mock_run:
        mock_run.return_value = ""

        with pytest.raises(Exception, match=r"Route .* not found"):
            get_route_url("nonexistent-route")


def test_validate_prometheus_endpoint():
    """Test Prometheus endpoint validation."""
    for endpoint in ALLOWED_PROMETHEUS_ENDPOINTS:
        validate_prometheus_endpoint(endpoint)

    validate_prometheus_endpoint("/api/v1/label/job/values")
    validate_prometheus_endpoint("/api/v1/label/__name__/values")

    with pytest.raises(Exception, match=r"Endpoint .* is not allowed"):
        validate_prometheus_endpoint("/api/v1/invalid")

    with pytest.raises(Exception, match=r"Endpoint .* is not allowed"):
        validate_prometheus_endpoint("/api/v2/query")


def test_validate_alertmanager_endpoint():
    """Test Alertmanager endpoint validation."""
    for endpoint in ALLOWED_ALERTMANAGER_ENDPOINTS:
        validate_alertmanager_endpoint(endpoint)

    with pytest.raises(Exception, match=r"Endpoint .* is not allowed"):
        validate_alertmanager_endpoint("/api/v2/invalid")


def test_validate_query_length():
    """Test query length validation."""
    validate_query_length("short query")

    long_query = "a" * (MAX_QUERY_LENGTH + 1)
    with pytest.raises(Exception, match=r"Query length .* exceeds maximum"):
        validate_query_length(long_query)


def test_convert_relative_time():
    """Test relative time conversion."""
    # Test 'now'
    result = convert_relative_time("now")
    assert "T" in result
    assert result.endswith("Z")

    # Test relative times
    result = convert_relative_time("-10m")
    assert "T" in result
    assert result.endswith("Z")

    result = convert_relative_time("-1h")
    assert "T" in result

    result = convert_relative_time("-1d")
    assert "T" in result

    result = convert_relative_time("-30s")
    assert "T" in result

    # Test absolute timestamps are unchanged
    timestamp = "2024-01-01T12:00:00Z"
    assert convert_relative_time(timestamp) == timestamp

    unix_timestamp = "1704110400"
    assert convert_relative_time(unix_timestamp) == unix_timestamp

    # Test invalid formats
    with pytest.raises(Exception, match="Invalid relative time format"):
        convert_relative_time("-10")

    with pytest.raises(Exception, match="Invalid relative time format"):
        convert_relative_time("-10x")

    with pytest.raises(Exception, match="Invalid time format"):
        convert_relative_time("invalid")


def test_sanitize_query_params():
    """Test query parameter sanitization."""
    sanitize_query_params({"query": "valid_query", "time": "now"})

    for char in BLOCKED_CHARS:
        with pytest.raises(Exception, match="contains blocked characters"):
            sanitize_query_params({"query": f"invalid{char}query"})

    long_value = "a" * (MAX_QUERY_LENGTH + 1)
    with pytest.raises(Exception, match="exceeds maximum length"):
        sanitize_query_params({"query": long_value})


def test_sanitize_query_params_promql():
    """Test query parameter sanitization with PromQL allowed."""
    # Parentheses should be allowed for PromQL
    sanitize_query_params(
        {"query": "rate(container_cpu_usage_seconds_total[5m])"}, allow_promql=True
    )

    # Other PromQL syntax should be allowed
    sanitize_query_params(
        {"query": "sum by(pod) (metric{label='value'})"}, allow_promql=True
    )

    # But backticks and semicolons should still be blocked
    with pytest.raises(Exception, match="contains blocked characters"):
        sanitize_query_params({"query": "invalid`query"}, allow_promql=True)

    with pytest.raises(Exception, match="contains blocked characters"):
        sanitize_query_params({"query": "invalid;query"}, allow_promql=True)


def test_query_api_endpoint(token_in_env):
    """Test API endpoint querying."""
    response_data = {"status": "success", "data": {"result": []}}

    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(response_data) + "\nHTTP_STATUS:200",
            stderr="",
        )

        result = query_api_endpoint(
            "https://thanos-querier.com",
            "/api/v1/query",
            {"query": "up"},
        )

        assert result == response_data
        assert "Authorization: Bearer fake-token" in mock_run.call_args[0][0]


def test_query_api_endpoint_with_promql(token_in_env):
    """Test API endpoint querying with PromQL containing parentheses."""
    response_data = {"status": "success", "data": {"result": []}}

    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(response_data) + "\nHTTP_STATUS:200",
            stderr="",
        )

        result = query_api_endpoint(
            "https://thanos-querier.com",
            "/api/v1/query",
            {"query": "rate(container_cpu_usage_seconds_total[5m])"},
            allow_promql=True,
        )

        assert result == response_data
        # Verify the query was URL-encoded properly
        call_args = mock_run.call_args[0][0]
        assert "curl" in call_args
        # The URL should contain the encoded query
        url_arg = next(arg for arg in call_args if "query=" in arg)
        assert "rate" in url_arg


def test_query_api_endpoint_with_error_response(token_in_env):
    """Test API endpoint querying with error response."""
    error_response = {"status": "error", "error": "query failed"}

    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(error_response) + "\nHTTP_STATUS:200",
            stderr="",
        )

        with pytest.raises(Exception, match="API returned error: query failed"):
            query_api_endpoint("https://api.com", "/api/v1/query", {"query": "up"})


def test_query_api_endpoint_size_limit(token_in_env):
    """Test API endpoint response size limit."""
    large_response = "x" * (MAX_RESPONSE_SIZE + 1) + "\nHTTP_STATUS:200"

    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=large_response,
            stderr="",
        )

        with pytest.raises(Exception, match=r"Response size .* exceeds maximum"):
            query_api_endpoint("https://api.com", "/api/v1/query")


def test_query_api_endpoint_invalid_json(token_in_env):
    """Test API endpoint with invalid JSON response."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not json\nHTTP_STATUS:200",
            stderr="",
        )

        with pytest.raises(Exception, match="Failed to parse API response"):
            query_api_endpoint("https://api.com", "/api/v1/query")


def test_query_api_endpoint_http_error(token_in_env):
    """Test API endpoint with HTTP error status."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="Error message\nHTTP_STATUS:404",
            stderr="",
        )

        with pytest.raises(Exception, match="API returned HTTP 404"):
            query_api_endpoint("https://api.com", "/api/v1/query")


def test_query_api_endpoint_empty_response(token_in_env):
    """Test API endpoint with empty response."""
    with patch("mcp_local.openshift.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="\nHTTP_STATUS:200",
            stderr="",
        )

        with pytest.raises(Exception, match="API returned empty response"):
            query_api_endpoint("https://api.com", "/api/v1/query")


def test_oc_query_prometheus(token_in_env):
    """Test Prometheus instant query tool."""
    response_data = {
        "status": "success",
        "data": {"resultType": "vector", "result": []},
    }

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        result = oc_query_prometheus("up{job='etcd'}")

        mock_route.assert_called_once_with("thanos-querier", "openshift-monitoring")
        mock_query.assert_called_once_with(
            "https://thanos-querier.com",
            "/api/v1/query",
            {"query": "up{job='etcd'}"},
            allow_promql=True,
        )

        assert json.loads(result) == response_data


def test_oc_query_prometheus_with_time(token_in_env):
    """Test Prometheus instant query with time parameter."""
    response_data = {"status": "success", "data": {"result": []}}

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        oc_query_prometheus("up", time="2024-01-01T12:00:00Z")

        mock_query.assert_called_once_with(
            "https://thanos-querier.com",
            "/api/v1/query",
            {"query": "up", "time": "2024-01-01T12:00:00Z"},
            allow_promql=True,
        )


def test_oc_query_prometheus_range(token_in_env):
    """Test Prometheus range query tool."""
    response_data = {
        "status": "success",
        "data": {"resultType": "matrix", "result": []},
    }

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        result = oc_query_prometheus_range(
            promql_query="up",
            start="2024-01-01T00:00:00Z",
            end="2024-01-01T01:00:00Z",
            step="1m",
        )

        mock_query.assert_called_once_with(
            "https://thanos-querier.com",
            "/api/v1/query_range",
            {
                "query": "up",
                "start": "2024-01-01T00:00:00Z",
                "end": "2024-01-01T01:00:00Z",
                "step": "1m",
            },
            allow_promql=True,
        )

        assert json.loads(result) == response_data


def test_oc_query_prometheus_range_with_relative_times(token_in_env):
    """Test Prometheus range query tool with relative time conversion."""
    response_data = {
        "status": "success",
        "data": {"resultType": "matrix", "result": []},
    }

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        result = oc_query_prometheus_range(
            promql_query="up",
            start="-10m",
            end="now",
            step="30s",
        )

        # Verify the call was made with converted timestamps
        call_args = mock_query.call_args[0]
        call_kwargs = mock_query.call_args[1]

        assert call_args[0] == "https://thanos-querier.com"
        assert call_args[1] == "/api/v1/query_range"

        params = call_args[2]
        assert params["query"] == "up"
        assert params["step"] == "30s"
        # Check that times were converted to RFC3339 format
        assert "T" in params["start"]
        assert params["start"].endswith("Z")
        assert "T" in params["end"]
        assert params["end"].endswith("Z")

        assert call_kwargs["allow_promql"] is True
        assert json.loads(result) == response_data


def test_oc_query_prometheus_simple_format(token_in_env):
    """Test Prometheus instant query with simple format."""
    response_data = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {"metric": {"pod": "test-pod"}, "value": [1234567890, "0.5"]},
            ],
        },
    }

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        result = oc_query_prometheus("up", output_format="simple")

        # Should return only the result array, not the full response
        parsed = json.loads(result)
        assert parsed == response_data["data"]["result"]


def test_oc_query_prometheus_range_simple_format(token_in_env):
    """Test Prometheus range query with simple format."""
    response_data = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"pod": "test-pod"},
                    "values": [[1234567890, "0.5"], [1234567920, "0.6"]],
                },
            ],
        },
    }

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://thanos-querier.com"
        mock_query.return_value = response_data

        result = oc_query_prometheus_range(
            promql_query="up",
            start="-10m",
            end="now",
            step="30s",
            output_format="simple",
        )

        # Should return only the result array, not the full response
        parsed = json.loads(result)
        assert parsed == response_data["data"]["result"]


def test_oc_query_alerts(token_in_env):
    """Test Alertmanager query tool."""
    response_data = [
        {
            "labels": {"alertname": "HighMemoryUsage"},
            "state": "firing",
        }
    ]

    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://alertmanager.com"
        mock_query.return_value = response_data

        result = oc_query_alerts(active_only=True)

        mock_route.assert_called_once_with("alertmanager-main", "openshift-monitoring")
        mock_query.assert_called_once_with(
            "https://alertmanager.com",
            "/api/v2/alerts",
            {"active": "true"},
        )

        assert json.loads(result) == response_data


def test_oc_query_alerts_all(token_in_env):
    """Test Alertmanager query for all alerts including silenced."""
    with patch("mcp_local.openshift.get_route_url") as mock_route, patch(
        "mcp_local.openshift.query_api_endpoint"
    ) as mock_query:
        mock_route.return_value = "https://alertmanager.com"
        mock_query.return_value = []

        oc_query_alerts(active_only=False)

        mock_query.assert_called_once_with(
            "https://alertmanager.com", "/api/v2/alerts", {}
        )


def test_oc_api_get(token_in_env):
    """Test Kubernetes API get tool."""
    response_data = {
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": [],
    }

    with patch("mcp_local.openshift.run_oc") as mock_run:
        mock_run.return_value = json.dumps(response_data)

        result = oc_api_get("api/v1/namespaces")

        mock_run.assert_called_once_with(["get", "--raw", "/api/v1/namespaces"])
        assert json.loads(result) == response_data


def test_oc_api_get_with_namespace(token_in_env):
    """Test Kubernetes API get with namespace scoping."""
    response_data = {"kind": "RouteList", "items": []}

    with patch("mcp_local.openshift.run_oc") as mock_run:
        mock_run.return_value = json.dumps(response_data)

        result = oc_api_get(
            "apis/route.openshift.io/v1/routes", namespace="openshift-monitoring"
        )

        expected_path = (
            "/apis/route.openshift.io/v1/namespaces/openshift-monitoring/routes"
        )
        mock_run.assert_called_once_with(["get", "--raw", expected_path])
        assert json.loads(result) == response_data


def test_oc_api_get_invalid_path(token_in_env):
    """Test Kubernetes API get with invalid resource path."""
    with pytest.raises(Exception, match="Resource path must start with"):
        oc_api_get("invalid/path")


def test_oc_api_get_non_json_response(token_in_env):
    """Test Kubernetes API get with non-JSON response."""
    with patch("mcp_local.openshift.run_oc") as mock_run:
        mock_run.return_value = "plain text response"

        result = oc_api_get("api/v1/namespaces")

        assert result == "plain text response"
