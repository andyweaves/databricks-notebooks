from databricks.sdk import WorkspaceClient


def get_workspace_client(host: str, token: str) -> str:

    return WorkspaceClient(host=host, token=token)


def get_serving_endpoints(workspace_client: WorkspaceClient) -> list:

    return workspace_client.serving_endpoints.list()
