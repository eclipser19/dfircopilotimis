import json
import os
from typing import Iterator, Optional

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

# Seconds before a single VQL call is abandoned. Ingesting a large flow
# (MFT, full EVTX sweep) streams for a long time, so it gets its own budget.
DEFAULT_TIMEOUT = int(os.environ.get("DFIR_VQL_TIMEOUT", "60"))
STREAM_TIMEOUT = int(os.environ.get("DFIR_VQL_STREAM_TIMEOUT", "3600"))


class VQLError(Exception):
    """Raised when a VQL call fails at the transport level (gRPC)."""


def _build_env(env: Optional[dict]) -> list:
    """VQLEnv values are strings; non-strings are JSON encoded."""
    env_list = []
    for k, v in (env or {}).items():
        value = v if isinstance(v, str) else json.dumps(v)
        env_list.append(api_pb2.VQLEnv(key=k, value=value))
    return env_list


class VQLClient:
    def __init__(self, config_path: str = "api_client.yaml"):
        self.config = pyvelociraptor.LoadConfigFile(config_path)
        self.creds = grpc.ssl_channel_credentials(
            root_certificates=self.config["ca_certificate"].encode("utf8"),
            private_key=self.config["client_private_key"].encode("utf8"),
            certificate_chain=self.config["client_cert"].encode("utf8")
        )
        self.channel = grpc.secure_channel(
            self.config["api_connection_string"],
            self.creds,
            (('grpc.ssl_target_name_override', "VelociraptorServer"),)
        )
        self.stub = api_pb2_grpc.APIStub(self.channel)

    def _request(self, query: str, env: Optional[dict]):
        return api_pb2.VQLCollectorArgs(
            env=_build_env(env),
            max_row=1000,
            max_wait=1,
            Query=[api_pb2.VQLRequest(Name="AgentQuery", VQL=query)]
        )

    def iter_rows(self, query: str, env: dict = None, logs: list = None,
                  timeout: int = STREAM_TIMEOUT) -> Iterator[dict]:
        """
        Streams result rows without holding the whole result set in memory.
        Velociraptor log lines (where VQL errors are reported) are appended to `logs`.
        Raises VQLError on transport failure.
        """
        try:
            for response in self.stub.Query(self._request(query, env), timeout=timeout):
                if response.log and logs is not None:
                    logs.append(response.log)
                if response.Response:
                    yield from json.loads(response.Response)
        except grpc.RpcError as e:
            raise VQLError(f"{e.code().name}: {e.details()}") from e

    def run_vql(self, query: str, env: dict = None, timeout: int = DEFAULT_TIMEOUT) -> dict:
        """
        Executes a VQL query. User-supplied values must go through `env`
        and be referenced by name in the query, never formatted into it.
        Returns a dict: {"results": [...], "log": "...", "error": optional}
        """
        logs = []
        results = []
        try:
            results.extend(self.iter_rows(query, env, logs, timeout))
        except VQLError as e:
            return {"error": str(e), "results": results, "log": "\n".join(logs)}
        return {"results": results, "log": "\n".join(logs)}


_client: Optional[VQLClient] = None


def get_vql() -> VQLClient:
    """Lazily connects, so importing the package doesn't need api_client.yaml."""
    global _client
    if _client is None:
        _client = VQLClient(os.environ.get("DFIR_API_CONFIG", "api_client.yaml"))
    return _client
