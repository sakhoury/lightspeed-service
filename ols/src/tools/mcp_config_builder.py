"""MCPConfigBuilder for building MultiServerMCPClient configuration."""

import logging
import os
from datetime import timedelta
from typing import Any

import httpx

from ols.app.models.config import MCPServerConfig
from ols.utils import checks

logger = logging.getLogger(__name__)


def _create_insecure_httpx_client_factory() -> Any:
    """Create a factory that produces httpx clients with SSL verification disabled."""

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        # Override verify to False, pass through all other arguments
        kwargs["verify"] = False
        return httpx.AsyncClient(**kwargs)

    return factory

# Constant, defining usage of kubernetes token
KUBERNETES_PLACEHOLDER = "kubernetes"


class MCPConfigBuilder:
    """Builds MCP config for MultiServerMCPClient."""

    def __init__(
        self, user_token: str, mcp_server_configs: list[MCPServerConfig]
    ) -> None:
        """Initialize the MCPConfigBuilder with user token and server config list."""
        self.user_token = user_token
        self.mcp_server_configs = mcp_server_configs

    def include_auth_to_stdio(self, server_envs: dict[str, str]) -> dict[str, str]:
        """Resolve OpenShift stdio env config."""
        logger.debug("Updating env configuration of openshift stdio mcp server")
        env = {**server_envs}

        # Determine which token to use
        # Priority: 1. User token from request, 2. Environment variable
        if self.user_token and self.user_token != "token-not-set":  # noqa: S105
            if "OC_USER_TOKEN" in env:
                logger.warning("OC_USER_TOKEN is set, overriding with actual user token.")
            env["OC_USER_TOKEN"] = self.user_token
        elif "OC_USER_TOKEN" in os.environ:
            logger.info(
                "Using OC_USER_TOKEN from environment (no user token from request)"
            )
            env["OC_USER_TOKEN"] = os.environ["OC_USER_TOKEN"]
        else:
            logger.warning(
                "No OC_USER_TOKEN available from request or environment. "
                "MCP tools may fail with authentication errors."
            )
            env["OC_USER_TOKEN"] = "token-not-set"  # noqa: S105

        if "KUBECONFIG" not in env:
            if "KUBECONFIG" in os.environ:
                logger.info("Using KUBECONFIG from environment.")
                env["KUBECONFIG"] = os.environ["KUBECONFIG"]
            elif (
                "KUBERNETES_SERVICE_HOST" in os.environ
                and "KUBERNETES_SERVICE_PORT" in os.environ
            ):
                logger.info("Using KUBERNETES_SERVICE_* from environment.")
                env["KUBERNETES_SERVICE_HOST"] = os.environ["KUBERNETES_SERVICE_HOST"]
                env["KUBERNETES_SERVICE_PORT"] = os.environ["KUBERNETES_SERVICE_PORT"]
            else:
                logger.error("Missing necessary KUBECONFIG/KUBERNETES_SERVICE_* envs.")
        return env

    def dump_client_config(self) -> dict[str, Any]:
        """Convert server configs to MultiServerMCPClient config format."""
        servers_conf: dict[str, Any] = {}

        for server_conf in self.mcp_server_configs:
            servers_conf[server_conf.name] = {
                "transport": server_conf.transport,
            }

            if server_conf.stdio:
                stdio_conf = server_conf.stdio.model_dump()
                if server_conf.name == "openshift":
                    stdio_conf["env"] = self.include_auth_to_stdio(
                        server_conf.stdio.env
                    )
                servers_conf[server_conf.name].update(stdio_conf)
                continue

            if server_conf.sse:
                sse_conf = server_conf.sse.model_dump()
                sse_conf["headers"] = self._resolve_tokens_to_value(sse_conf["headers"])
                servers_conf[server_conf.name].update(sse_conf)
                continue

            if server_conf.streamable_http:
                http_conf = server_conf.streamable_http.model_dump()
                http_conf["headers"] = self._resolve_tokens_to_value(
                    http_conf["headers"]
                )
                # Extract verify_ssl before updating (not a langchain-mcp option)
                verify_ssl = http_conf.pop("verify_ssl", True)
                servers_conf[server_conf.name].update(http_conf)
                # Note: Streamable HTTP transport expects timedelta instead of
                # int as for the sse - blame langchain-mcp-adapters for
                # inconsistency
                for timeout in ("timeout", "sse_read_timeout"):
                    servers_conf[server_conf.name][timeout] = timedelta(
                        seconds=servers_conf[server_conf.name][timeout]  # type: ignore [assignment]
                    )
                # Add custom httpx client factory if SSL verification is disabled
                if not verify_ssl:
                    logger.warning(
                        "SSL verification disabled for MCP server '%s'",
                        server_conf.name,
                    )
                    servers_conf[server_conf.name][
                        "httpx_client_factory"
                    ] = _create_insecure_httpx_client_factory()

        return servers_conf

    def _resolve_tokens_to_value(self, headers: dict[str, str]) -> dict[str, Any]:
        """Convert header definitions to values."""
        updated = {}
        for name, value in headers.items():
            if value == KUBERNETES_PLACEHOLDER:
                updated[name] = f"Bearer {self.user_token}"
            else:
                try:
                    # load token value
                    with open(value, "r", encoding="utf-8") as token_store:
                        token = token_store.read().strip()
                    updated[name] = token
                except Exception as e:
                    raise checks.InvalidConfigurationError(
                        f"token value refers to non existent file  '{value}', error {e}"
                    )
        return updated
