import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

@dataclass
class GCPConfig:
    project_id: str = os.getenv("GCP_PROJECT_ID", "")
    location: str = os.getenv("GCP_LOCATION", "us-central1")

    def validate(self) -> None:
        if not self.project_id:
            raise ValueError("Brak GCP_PROJECT_ID w pliku .env! Podaj Identyfikator Projektu z GCP.")

@dataclass
class AppConfig:
    
    gcp: GCPConfig = field(default_factory=GCPConfig)
    target_model: str = os.getenv("TARGET_MODEL", "gemini-2.5-flash")
    rate_limit_delay: float = float(os.getenv("RATE_LIMIT_DELAY", "0.2"))

    def __post_init__(self):
        self.gcp.validate()

config = AppConfig()