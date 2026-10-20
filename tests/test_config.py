import pytest
from config import GCPConfig, AppConfig

def test_gcp_config_missing_project_id():
    """Testuje, czy walidacja rzuca błąd, gdy brak ID projektu GCP."""
    config = GCPConfig(project_id="")
    with pytest.raises(ValueError, match="Brak GCP_PROJECT_ID"):
        config.validate()

def test_gcp_config_valid_project_id():
    """Testuje poprawną konfigurację GCP."""
    config = GCPConfig(project_id="my-test-project-123")
    try:
        config.validate()
    except ValueError:
        pytest.fail("validate() rzuciło błąd dla poprawnego ID projektu!")

def test_app_config_defaults():
    """Sprawdza domyślne wartości konfiguracji aplikacji."""
    gcp = GCPConfig(project_id="test-proj")
    app_config = AppConfig(gcp=gcp)
    
    assert app_config.target_model == "gemini-2.5-flash"
    assert isinstance(app_config.rate_limit_delay, float)