import requests

from integrations.http_safety import public_https_base


class JiraProvider:
    def __init__(self, base_url: str, email: str):
        self.base_url = public_https_base(base_url)
        self.email = (email or "").strip()
        if "@" not in self.email:
            raise ValueError("Email Jira inválido")

    def _auth(self, credential: str):
        return self.email, credential

    def validate(self, credential: str) -> dict:
        response = requests.get(f"{self.base_url}/rest/api/3/myself", auth=self._auth(credential), headers={"Accept": "application/json"}, timeout=12)
        if response.status_code != 200:
            raise ValueError("Falha ao validar as credenciais Jira")
        data = response.json()
        return {"account": data.get("displayName") or self.email, "email": self.email, "base_url": self.base_url}

    def list_projects(self, credential: str) -> list[dict]:
        response = requests.get(f"{self.base_url}/rest/api/3/project/search", auth=self._auth(credential), headers={"Accept": "application/json"}, params={"maxResults": 100}, timeout=20)
        if response.status_code != 200:
            raise ValueError("Falha ao sincronizar projetos Jira")
        return [{"key": item.get("key"), "name": item.get("name")} for item in response.json().get("values", []) if item.get("key")]

    def create_issue(self, credential: str, project_key: str, summary: str, description: str) -> dict:
        body = {"fields": {"project": {"key": project_key}, "summary": summary[:255], "issuetype": {"name": "Task"}, "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": description[:8000]}]}]}}}
        response = requests.post(f"{self.base_url}/rest/api/3/issue", auth=self._auth(credential), headers={"Accept": "application/json", "Content-Type": "application/json"}, json=body, timeout=20)
        if response.status_code not in {200, 201}:
            raise ValueError("Falha ao criar tarefa no Jira")
        data = response.json()
        return {"key": data.get("key"), "url": f"{self.base_url}/browse/{data.get('key')}"}
