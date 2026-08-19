import requests

from integrations.base import IntegrationProvider


class GitHubProvider(IntegrationProvider):
    api_url = "https://api.github.com"

    def _headers(self, credential: str) -> dict:
        return {"Authorization": f"Bearer {credential}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def validate(self, credential: str) -> dict:
        response = requests.get(f"{self.api_url}/user", headers=self._headers(credential), timeout=10)
        if response.status_code != 200:
            raise ValueError("GitHub credential validation failed")
        data = response.json()
        return {"account": data.get("login"), "account_id": data.get("id")}

    def sync_assets(self, credential: str) -> list[dict]:
        response = requests.get(f"{self.api_url}/user/repos", headers=self._headers(credential), params={"per_page": 100, "sort": "updated"}, timeout=15)
        if response.status_code != 200:
            raise ValueError("GitHub repository sync failed")
        return [{"name": repo.get("full_name"), "url": repo.get("html_url"), "private": repo.get("private", False), "default_branch": repo.get("default_branch")} for repo in response.json() if repo.get("full_name")]
