from abc import ABC, abstractmethod


class AbstractPlugin(ABC):

    @abstractmethod
    def handle_data(self, data: str, **kwargs) -> str:
        pass
