import base64
import requests

from integrations.base import IntegrationProvider


class AzureDevOpsProvider(IntegrationProvider):
    def __init__(self, organization: str):
        value = (organization or "").strip()
        if not value or not value.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Organização Azure DevOps inválida")
        self.organization = value
        self.base_url = f"https://dev.azure.com/{value}"

    @staticmethod
    def _headers(credential: str) -> dict:
        encoded = base64.b64encode(f":{credential}".encode()).decode()
        return {"Authorization": f"Basic {encoded}", "Accept": "application/json"}

    def validate(self, credential: str) -> dict:
        response = requests.get(f"{self.base_url}/_apis/projects", headers=self._headers(credential), params={"api-version": "7.1", "$top": 1}, timeout=15)
        if response.status_code != 200:
            raise ValueError("Falha ao validar o PAT do Azure DevOps")
        return {"account": self.organization, "base_url": self.base_url}

    def sync_assets(self, credential: str) -> list[dict]:
        headers = self._headers(credential)
        projects_response = requests.get(f"{self.base_url}/_apis/projects", headers=headers, params={"api-version": "7.1", "$top": 100}, timeout=20)
        if projects_response.status_code != 200:
            raise ValueError("Falha ao listar projetos Azure DevOps")
        repositories = []
        for project in projects_response.json().get("value", [])[:100]:
            project_id = project.get("id")
            response = requests.get(f"{self.base_url}/{project_id}/_apis/git/repositories", headers=headers, params={"api-version": "7.1"}, timeout=20)
            if response.status_code != 200:
                continue
            for repo in response.json().get("value", []):
                if repo.get("name"):
                    repositories.append({"name": f"{project.get('name')}/{repo['name']}", "url": repo.get("webUrl"), "private": True, "default_branch": (repo.get("defaultBranch") or "").replace("refs/heads/", "")})
        return repositories[:500]
