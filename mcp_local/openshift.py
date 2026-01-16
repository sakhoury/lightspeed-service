"""OpenShift CLI tools."""

import json
import logging
import os
import re
import subprocess
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("oc_cli_tools")


BLOCKED_CHARS = (";", "&", "|", "`", "$", "(", ")", "<", ">", "\\")
BLOCKED_CHARS_DETECTED_MSG = (
    f"Error: arguments contain blocked characters: {BLOCKED_CHARS}"
)
SECRET_NOT_ALLOWED_MSG = (
    "Error: 'secret' or 'secrets' are not allowed in arguments"  # noqa: S105
)

# API endpoint patterns for validation
ALLOWED_PROMETHEUS_ENDPOINTS = {
    "/api/v1/query",
    "/api/v1/query_range",
    "/api/v1/series",
    "/api/v1/labels",
}
ALLOWED_PROMETHEUS_LABEL_PATTERN = re.compile(r"^/api/v1/label/[^/]+/values$")

ALLOWED_ALERTMANAGER_ENDPOINTS = {
    "/api/v2/alerts",
    "/api/v2/silences",
    "/api/v1/alerts",
}

# Maximum response size (10MB)
MAX_RESPONSE_SIZE = 10 * 1024 * 1024

# Maximum query length to prevent DoS
MAX_QUERY_LENGTH = 10000


def strip_args_for_oc_command(args: list[str]) -> list[str]:
    """Sanitize arguments for `oc` CLI commands if LLM adds extras."""
    # fixes these cases:
    # - extra spaces in args: ["pod "]
    # - extra commands in args: ["oc", "get", "pod"]
    # - two commands as one in args: ["pod my-pod"]
    remove_args = {"oc", "get", "describe", "logs", "status", "adm", "top"}
    split_args = [
        arg for arg in " ".join(args).split() if arg and arg not in remove_args
    ]
    return split_args


def raise_for_unacceptable_args(args: list[str]) -> None:
    """Check & raise exception if arguments are unacceptable."""
    arg_str = " ".join(args)

    if any(char in arg_str for char in BLOCKED_CHARS):
        logger.error("Blocked characters found in argument: %s", arg_str)
        raise Exception(BLOCKED_CHARS_DETECTED_MSG)

    if "secret" in arg_str:
        logger.error("'secret' keyword found in argument: %s", arg_str)
        raise Exception(SECRET_NOT_ALLOWED_MSG)


def redact_token(text: str, token: str) -> str:
    """Redact token from text."""
    if not token or token == "token-not-set":  # noqa: S105
        return text
    return text.replace(token, "<redacted>")


def run_oc(args: list[str]) -> str:
    """Run `oc` CLI with provided arguments and command."""
    # Currently user token is sent to server using env var.
    token = os.environ.get("OC_USER_TOKEN", "token-not-set")

    try:
        result = subprocess.run(  # noqa: S603
            ["oc", *args, "--token", token],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
    except Exception:
        # if token was used, redact the error to ensure it is not leaked
        raise Exception(redact_token(traceback.format_exc(), token))

    # some commands returns empty stdout and message like "namespace not found"
    # in stderr, but with return code 0
    if result.returncode == 0:
        response = result.stdout if result.stdout != "" else result.stderr
        return redact_token(response, token)
    raise Exception(redact_token(result.stderr, token))


def safe_run_oc(commands: list[str], args: list[str]) -> str:
    """Run `oc` CLI with provided arguments and command."""
    raise_for_unacceptable_args(args)

    return run_oc([*commands, *strip_args_for_oc_command(args)])


def get_route_url(route_name: str, namespace: str = "openshift-monitoring") -> str:
    """Get route URL for a service in OpenShift.

    Args:
        route_name: Name of the route
        namespace: Namespace where route exists

    Returns:
        Full HTTPS URL for the route

    Raises:
        Exception: If route cannot be found or accessed
    """
    try:
        result = run_oc([
            "get",
            "route",
            route_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.spec.host}",
        ])
        host = result.strip()
        if not host:
            raise Exception(f"Route {route_name} not found in namespace {namespace}")
        return f"https://{host}"
    except Exception as e:
        raise Exception(f"Failed to get route URL for {route_name}: {e}")


def validate_prometheus_endpoint(endpoint: str) -> None:
    """Validate Prometheus API endpoint path.

    Args:
        endpoint: Endpoint path to validate

    Raises:
        Exception: If endpoint is not allowed
    """
    if endpoint not in ALLOWED_PROMETHEUS_ENDPOINTS:
        if not ALLOWED_PROMETHEUS_LABEL_PATTERN.match(endpoint):
            raise Exception(
                f"Endpoint {endpoint} is not allowed. "
                f"Allowed endpoints: {ALLOWED_PROMETHEUS_ENDPOINTS}"
            )


def validate_alertmanager_endpoint(endpoint: str) -> None:
    """Validate Alertmanager API endpoint path.

    Args:
        endpoint: Endpoint path to validate

    Raises:
        Exception: If endpoint is not allowed
    """
    if endpoint not in ALLOWED_ALERTMANAGER_ENDPOINTS:
        raise Exception(
            f"Endpoint {endpoint} is not allowed. "
            f"Allowed endpoints: {ALLOWED_ALERTMANAGER_ENDPOINTS}"
        )


def validate_query_length(query: str) -> None:
    """Validate query length to prevent DoS.

    Args:
        query: Query string to validate

    Raises:
        Exception: If query exceeds maximum length
    """
    if len(query) > MAX_QUERY_LENGTH:
        raise Exception(
            f"Query length {len(query)} exceeds maximum {MAX_QUERY_LENGTH}"
        )


def convert_relative_time(time_str: str) -> str:
    """Convert relative time strings to RFC3339 timestamps.

    Args:
        time_str: Time string (can be relative like 'now', '-10m', or absolute)

    Returns:
        RFC3339 timestamp string

    Examples:
        'now' -> '2024-01-01T12:00:00Z'
        '-10m' -> '2024-01-01T11:50:00Z'
        '-1h' -> '2024-01-01T11:00:00Z'
        '-1d' -> '2023-12-31T12:00:00Z'
        '2024-01-01T12:00:00Z' -> '2024-01-01T12:00:00Z' (unchanged)
    """
    # If already a timestamp (contains T or is numeric), return as-is
    if "T" in time_str or time_str.isdigit():
        return time_str

    # Handle 'now'
    if time_str == "now":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Handle relative times like '-10m', '-1h', '-1d'
    if time_str.startswith("-"):
        # Parse the relative time
        match = re.match(r"^-(\d+)([smhd])$", time_str)
        if not match:
            raise Exception(
                f"Invalid relative time format: {time_str}. "
                "Expected format: -<number><unit> where unit is s/m/h/d"
            )

        value = int(match.group(1))
        unit = match.group(2)

        # Calculate the time delta
        if unit == "s":
            delta = timedelta(seconds=value)
        elif unit == "m":
            delta = timedelta(minutes=value)
        elif unit == "h":
            delta = timedelta(hours=value)
        elif unit == "d":
            delta = timedelta(days=value)
        else:
            raise Exception(f"Invalid time unit: {unit}")

        target_time = datetime.now(timezone.utc) - delta
        return target_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # If we can't parse it, raise an error
    raise Exception(
        f"Invalid time format: {time_str}. "
        "Expected 'now', relative time like '-10m', or RFC3339 timestamp"
    )


def sanitize_query_params(
    params: dict[str, str], allow_promql: bool = False
) -> None:
    """Validate query parameters for security.

    Args:
        params: Query parameters to validate
        allow_promql: If True, allows PromQL-safe characters like parentheses

    Raises:
        Exception: If parameters contain unsafe characters
    """
    # For PromQL queries, we need to allow parentheses and other PromQL syntax
    # The real security concerns are handled by:
    # 1. URL encoding (prevents injection into HTTP layer)
    # 2. Length limits (prevents DoS)
    # 3. Endpoint whitelisting (prevents unauthorized API access)
    blocked: tuple[str, ...]
    if allow_promql:
        # For PromQL, only block characters that could cause issues in HTTP context
        # Shell metacharacters are irrelevant since we're not using shell=True
        blocked = (";", "`", "\\")
    else:
        blocked = BLOCKED_CHARS

    for key, value in params.items():
        if any(char in str(value) for char in blocked):
            raise Exception(
                f"Query parameter '{key}' contains blocked characters: {blocked}"
            )
        if len(str(value)) > MAX_QUERY_LENGTH:
            raise Exception(
                f"Query parameter '{key}' exceeds maximum length {MAX_QUERY_LENGTH}"
            )


def query_api_endpoint(  # noqa: C901
    base_url: str,
    endpoint: str,
    params: dict[str, str] | None = None,
    allow_promql: bool = False,
) -> dict[str, Any]:
    """Query an API endpoint using oc and curl.

    Args:
        base_url: Base URL of the API
        endpoint: API endpoint path
        params: Optional query parameters
        allow_promql: If True, allows PromQL-safe characters in parameters

    Returns:
        Parsed JSON response from API

    Raises:
        Exception: If query fails or response is invalid
    """
    token = os.environ.get("OC_USER_TOKEN", "token-not-set")

    # Build URL with query parameters
    url = f"{base_url}{endpoint}"
    if params:
        sanitize_query_params(params, allow_promql=allow_promql)
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    try:
        # Use curl with HTTP status code checking
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "curl",
                "-s",
                "-w",
                "\nHTTP_STATUS:%{http_code}",  # Append HTTP status to response
                "-k",  # Skip TLS verification (cluster may use self-signed certs)
                "-H",
                f"Authorization: Bearer {token}",
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=30,
        )

        if result.returncode != 0:
            error_msg = redact_token(result.stderr, token)
            raise Exception(f"API query failed: {error_msg}")

        # Extract HTTP status code from response
        response_text = result.stdout
        http_status = "000"
        if "\nHTTP_STATUS:" in response_text:
            parts = response_text.rsplit("\nHTTP_STATUS:", 1)
            response_text = parts[0]
            http_status = parts[1].strip()

        # Check HTTP status code
        if not http_status.startswith("2"):
            logger.error(
                "HTTP error %s from %s. Response: %s",
                http_status,
                url,
                response_text[:500],
            )
            raise Exception(
                f"API returned HTTP {http_status}. "
                f"Response: {response_text[:200]}"
            )

        # Check response size
        if len(response_text) > MAX_RESPONSE_SIZE:
            raise Exception(
                f"Response size {len(response_text)} exceeds maximum {MAX_RESPONSE_SIZE}"
            )

        # Check if response is empty
        if not response_text or not response_text.strip():
            logger.error("Empty response from %s", url)
            raise Exception("API returned empty response")

        # Parse JSON response
        try:
            response = json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON. Response: %s", response_text[:500])
            raise Exception(
                f"Failed to parse API response as JSON: {e}. "
                f"Response: {response_text[:200]}"
            )

        # Check for API error responses
        if isinstance(response, dict):
            if response.get("status") == "error":
                error_msg = response.get("error", "Unknown error")
                raise Exception(f"API returned error: {error_msg}")

        return response

    except Exception as e:
        # Redact token from any error messages
        error_msg = redact_token(str(e), token)
        raise Exception(error_msg)


@mcp.tool()
def oc_get(oc_get_args: list[str]) -> str:
    """Display one or many resources from OpenShift cluster.

    Standard `oc` flags and options are valid.

    Namespace is optional argument. If not provided, the default namespace will be used.
    To specify a namespace, use the `--namespace <namespace>` or `-n <namespace>`.

    Args:
        oc_get_args: Arguments for oc get

    Examples:
        # List all pods in ps output format.
        oc get pods

        # List all pods in ps output format with more information (such as node name).
        oc get pods -o wide

        # List events for cluster
        oc get events

        # List a single replication controller with specified NAME in ps output format.
        oc get replicationcontroller web

        # List deployments in JSON output format, in the "v1" version of the "apps" API group:
        oc get deployments.v1.apps -o json

        # List a pod identified by type and name specified in "pod.yaml" in JSON output format.
        oc get -f pod.yaml -o json

        # List all replication controllers and services together in ps output format.
        oc get rc,services
    """
    return safe_run_oc(["get"], oc_get_args)


@mcp.tool()
def oc_describe(oc_describe_args: list[str]) -> str:
    """Show details of a specific resource or group of resources.

    Print a detailed description of the selected resources, including related resources such as events or controllers.
    You may select a single object by name, all objects of that type, provide a name prefix, or label selector.

    Namespace is optional argument. If not provided, the default namespace will be used.
    To specify a namespace, use the `--namespace <namespace>` or `-n <namespace>`.

    Args:
        oc_describe_args: Arguments for oc describe

    Examples:
        # Describe a node
        oc describe nodes kubernetes-node-emt8.c.myproject.internal

        # Describe a pod
        oc describe pods/nginx

        # Describe a pod identified by type and name in "pod.json"
        oc describe -f pod.json

        # Describe all pods
        oc describe pods

        # Describe pods by label name=myLabel
        oc describe po -l name=myLabel

        # Describe all pods managed by the 'frontend' replication controller
        oc describe pods frontend
    """  # noqa: E501
    return safe_run_oc(["describe"], oc_describe_args)


@mcp.tool()
def oc_logs(oc_logs_args: list[str]) -> str:
    """Print the logs for a resource.

    Supported resources are builds, build configs (bc), deployment configs (dc), and pods.
    When a pod is specified and has more than one container, the container name should be specified via -c.
    When a build config or deployment config is specified, you can view the logs for a particular version of it via --version.

    Namespace is optional argument. If not provided, the default namespace will be used.
    To specify a namespace, use the `--namespace <namespace>` or `-n <namespace>`.

    Args:
        oc_logs_args: Arguments for oc logs

    Examples:
        # Start streaming the logs of the most recent build of the openldap build config.
        oc logs -f bc/openldap

        # Get the logs of the first deployment for the mysql deployment config.
        oc logs --version=1 dc/mysql

        # Return a snapshot of ruby-container logs from pod backend.
        oc logs backend -c ruby-container

        # Start streaming of ruby-container logs from pod backend.
        oc logs -f pod/backend -c ruby-container
    """  # noqa: E501
    return safe_run_oc(["logs"], oc_logs_args)


@mcp.tool()
def oc_status(oc_status_args: list[str]) -> str:
    """Show a high level overview of the current project.

    This command will show services, deployment configs, build configurations, & active deployments.
    If you have any misconfigured components information about them will be shown.
    For more information about individual items, use the describe command \
    (e.g. oc describe buildconfig, oc describe deploymentconfig, oc describe service).

    Namespace is optional argument. If not provided, the default namespace will be used.
    To specify a namespace, use the `--namespace <namespace>` or `-n <namespace>`.

    Args:
        oc_status_args: Arguments for oc status

    Examples:
        # See an overview of the current project.
        oc status

        # Export the overview of the current project in an svg file.
        oc status -o dot | dot -T svg -o project.svg

        # See an overview of the current project including details for any identified issues.
        oc --suggest
    """
    return safe_run_oc(["status"], oc_status_args)


@mcp.tool()
def show_pods_resource_usage() -> str:
    """Show resource usage (CPU and memory) for all pods accross all namespaces.

    Usecases:
        - Pods resource usage monitoring.
        - Resource allocation monitoring.
        - Average resources consumption.

    The output format is:
        NAMESPACE    NAME                                              CPU(cores)  MEMORY(bytes)
        kube-system  konnectivity-agent-qwnsd                          1m          24Mi
        kube-system  kube-apiserver-proxy-ip-10-0-130-91.ec2.internal  2m          13Mi
    """
    return run_oc(["adm", "top", "pods", "-A"])


@mcp.tool()
def oc_adm_top(oc_adm_top_args: list[str]) -> str:
    """Show usage statistics of resources on the server.

    This command analyzes resources managed by the platform and presents current usage statistics.

    When no options are provided, the command will list given resource in default namespace.
    To get the resources across namespaces, use `-A` flag.

    Args:
        oc_adm_top_args: Arguments for oc adm top

    Usage:
        oc adm top [commands] [options]

    Available Commands:
        images       Show usage statistics for Images
        imagestreams Show usage statistics for ImageStreams
        node         Display Resource (CPU/Memory/Storage) usage of nodes
        pod          Display Resource (CPU/Memory/Storage) usage of pods

    Options:
        --namespace <namespace>
            Lists resources for specified namespace.
    """
    return safe_run_oc(["adm", "top"], oc_adm_top_args)


@mcp.tool()
def oc_query_prometheus(
    promql_query: str, time: str | None = None, output_format: str = "full"
) -> str:
    """Query Prometheus/Thanos for metrics using PromQL.

    Execute instant PromQL queries against the cluster's Thanos Querier.
    Returns current metric values at the specified time (or current time if not specified).

    Args:
        promql_query: PromQL query string
        time: Optional RFC3339 or Unix timestamp for instant query.
              If not provided, uses current time.
        output_format: Output format - "full" (complete API response) or "simple" (data only).
                       Default: "full"

    Returns:
        JSON string with query results

    Examples:
        # Get current CPU usage by pod
        oc_query_prometheus("sum by(pod) (rate(container_cpu_usage_seconds_total[5m]))")

        # Get memory usage for specific namespace (simplified format)
        oc_query_prometheus(
            "sum by(namespace) (container_memory_usage_bytes{namespace='openshift-monitoring'})",
            output_format="simple"
        )

        # Count running pods
        oc_query_prometheus("count(kube_pod_status_phase{phase='Running'})")

        # Get CPU usage at specific time
        oc_query_prometheus(
            "rate(container_cpu_usage_seconds_total[5m])",
            time="2024-01-01T12:00:00Z"
        )

        # Get node capacity
        oc_query_prometheus("sum(kube_node_status_capacity{resource='cpu'})")

        # Check etcd health
        oc_query_prometheus("up{job='etcd'}")
    """
    validate_query_length(promql_query)

    # Get Thanos Querier route
    base_url = get_route_url("thanos-querier", "openshift-monitoring")

    # Build query parameters
    params: dict[str, str] = {"query": promql_query}
    if time:
        params["time"] = time

    # Query the API
    endpoint = "/api/v1/query"
    validate_prometheus_endpoint(endpoint)

    try:
        response = query_api_endpoint(base_url, endpoint, params, allow_promql=True)

        # Return simplified format if requested
        if output_format == "simple" and isinstance(response, dict):
            if response.get("status") == "success":
                return json.dumps(response.get("data", {}).get("result", []), indent=2)

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error("Prometheus query failed: %s", e)
        raise


@mcp.tool()
def oc_query_prometheus_range(
    promql_query: str, start: str, end: str, step: str = "15s", output_format: str = "full"
) -> str:
    """Query Prometheus/Thanos for time-series metrics over a range.

    Execute range PromQL queries for historical metrics data.
    Returns metric values over a specified time range with given resolution.

    Args:
        promql_query: PromQL query string
        start: Start time (RFC3339/Unix timestamp, or relative like '-10m')
        end: End time (RFC3339/Unix timestamp, or relative like 'now')
        step: Query resolution step (e.g., "15s", "1m", "5m"). Default: "15s"
        output_format: Output format - "full" (complete API response) or "simple" (data only).
                       Default: "full"

    Returns:
        JSON string with time-series query results

    Examples:
        # Get CPU usage over last hour
        oc_query_prometheus_range(
            promql_query="rate(container_cpu_usage_seconds_total[5m])",
            start="2024-01-01T12:00:00Z",
            end="2024-01-01T13:00:00Z",
            step="1m"
        )

        # Get memory usage trend using relative times (simplified format)
        oc_query_prometheus_range(
            promql_query="container_memory_usage_bytes{pod='my-pod'}",
            start="-1h",
            end="now",
            step="30s",
            output_format="simple"
        )

        # Monitor request rate over time
        oc_query_prometheus_range(
            promql_query="rate(http_requests_total[5m])",
            start="-10m",
            end="now",
            step="30s"
        )
    """
    validate_query_length(promql_query)

    # Get Thanos Querier route
    base_url = get_route_url("thanos-querier", "openshift-monitoring")

    # Convert relative times to RFC3339 timestamps
    start_time = convert_relative_time(start)
    end_time = convert_relative_time(end)

    # Build query parameters
    params = {
        "query": promql_query,
        "start": start_time,
        "end": end_time,
        "step": step,
    }

    # Query the API
    endpoint = "/api/v1/query_range"
    validate_prometheus_endpoint(endpoint)

    try:
        response = query_api_endpoint(base_url, endpoint, params, allow_promql=True)

        # Return simplified format if requested
        if output_format == "simple" and isinstance(response, dict):
            if response.get("status") == "success":
                return json.dumps(response.get("data", {}).get("result", []), indent=2)

        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error("Prometheus range query failed: %s", e)
        raise


@mcp.tool()
def oc_query_alerts(active_only: bool = True) -> str:
    """Query Alertmanager for active and pending alerts.

    Retrieve alerts from the cluster's Alertmanager instance.
    Useful for monitoring cluster health and detecting issues.

    Args:
        active_only: Only return active alerts (excludes silenced alerts).
                     Default: True

    Returns:
        JSON string with alert information

    Examples:
        # Get all active alerts
        oc_query_alerts(active_only=True)

        # Get all alerts including silenced ones
        oc_query_alerts(active_only=False)
    """
    # Get Alertmanager route
    base_url = get_route_url("alertmanager-main", "openshift-monitoring")

    # Build query parameters
    params: dict[str, str] = {}
    if active_only:
        params["active"] = "true"

    # Query the API
    endpoint = "/api/v2/alerts"
    validate_alertmanager_endpoint(endpoint)

    try:
        response = query_api_endpoint(base_url, endpoint, params)
        return json.dumps(response, indent=2)
    except Exception as e:
        logger.error("Alertmanager query failed: %s", e)
        raise


@mcp.tool()
def oc_api_get(resource_path: str, namespace: str | None = None) -> str:
    """Query Kubernetes/OpenShift API resources directly.

    Access API resources through the Kubernetes API server.
    Useful for querying custom resources, aggregated APIs, or specific resource details
    not easily accessible through standard oc commands.

    Args:
        resource_path: API resource path relative to API server
                      (e.g., "apis/route.openshift.io/v1/routes")
        namespace: Optional namespace to scope the query.
                  If provided, query will be scoped to namespace.

    Returns:
        JSON string with API response

    Examples:
        # Get all routes in monitoring namespace
        oc_api_get("apis/route.openshift.io/v1/routes", namespace="openshift-monitoring")

        # Get cluster operators
        oc_api_get("apis/config.openshift.io/v1/clusteroperators")

        # Get all namespaces
        oc_api_get("api/v1/namespaces")

        # Get specific configmap
        oc_api_get("api/v1/configmaps", namespace="kube-system")

        # Get custom resources
        oc_api_get("apis/custom.example.com/v1/myresources", namespace="default")
    """
    # Validate resource path format
    if not resource_path.startswith(("api/", "apis/")):
        raise Exception(
            "Resource path must start with 'api/' or 'apis/'. "
            f"Got: {resource_path}"
        )

    # Build the oc command
    cmd = ["get", "--raw", f"/{resource_path}"]

    # Add namespace filter if provided
    if namespace:
        # For namespaced resources, modify the path
        if "/namespaces/" not in resource_path:
            parts = resource_path.split("/")
            if len(parts) >= 3:
                api_prefix = "/".join(parts[:3])
                resource_type = "/".join(parts[3:]) if len(parts) > 3 else ""
                resource_path = (
                    f"{api_prefix}/namespaces/{namespace}/{resource_type}"
                )
                cmd = ["get", "--raw", f"/{resource_path}"]

    try:
        result = run_oc(cmd)
        # Parse and re-format JSON for consistent output
        parsed = json.loads(result)
        return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        # If not JSON, return as-is
        return result
    except Exception as e:
        logger.error("API query failed: %s", e)
        raise


if __name__ == "__main__":
    mcp.run(transport="stdio")
