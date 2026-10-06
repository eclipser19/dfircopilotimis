import json
import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

class VQLClient:
    def __init__(self, config_path="api_client.yaml"):
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

    def run_vql(self, query: str, env: dict = None) -> dict:
        """
        Executes a VQL query. 
        Returns a dict: {"results": [...], "log": "..."}
        """
        env_list = []
        if env:
            for k, v in env.items():
                env_list.append(api_pb2.VQLEnv(key=k, value=str(v)))

        request = api_pb2.VQLCollectorArgs(
            env=env_list,
            Query=[api_pb2.VQLRequest(Name="AgentQuery", VQL=query)]
        )

        results = []
        logs = []
        try:
            for response in self.stub.Query(request):
                if response.Response:
                    results.extend(json.loads(response.Response))
                if response.log:
                    logs.append(response.log)
        except Exception as e:
            return {"error": str(e), "results": [], "log": "\n".join(logs)}

        return {"results": results, "log": "\n".join(logs)}

# Global instance for tool use
vql = VQLClient()
