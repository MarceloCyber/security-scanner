from abc import ABC, abstractmethod


class IntegrationProvider(ABC):
    @abstractmethod
    def validate(self, credential: str) -> dict:
        raise NotImplementedError

    @abstractmethod
    def sync_assets(self, credential: str) -> list[dict]:
        raise NotImplementedError
