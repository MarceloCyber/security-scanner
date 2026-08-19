import requests

from integrations.base import IntegrationProvider
from integrations.http_safety import public_https_base


class GitLabProvider(IntegrationProvider):
    def __init__(self, base_url: str = "https://gitlab.com"):
        self.base_url = public_https_base(base_url)
        self.api_url = f"{self.base_url}/api/v4"

    @staticmethod
    def _headers(credential: str) -> dict:
        return {"PRIVATE-TOKEN": credential, "Accept": "application/json"}

    def validate(self, credential: str) -> dict:
        response = requests.get(f"{self.api_url}/user", headers=self._headers(credential), timeout=12)
        if response.status_code != 200:
            raise ValueError("Falha ao validar o token GitLab")
        data = response.json()
        return {"account": data.get("username"), "account_id": data.get("id"), "base_url": self.base_url}

    def sync_assets(self, credential: str) -> list[dict]:
        response = requests.get(f"{self.api_url}/projects", headers=self._headers(credential), params={"membership": "true", "simple": "true", "per_page": 100, "order_by": "last_activity_at"}, timeout=20)
        if response.status_code != 200:
            raise ValueError("Falha ao sincronizar projetos GitLab")
        return [{"name": item.get("path_with_namespace"), "url": item.get("web_url"), "private": item.get("visibility") != "public", "default_branch": item.get("default_branch")} for item in response.json() if item.get("path_with_namespace")]
