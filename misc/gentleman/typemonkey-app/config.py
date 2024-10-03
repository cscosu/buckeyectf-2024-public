from pathlib import Path
from secrets import token_urlsafe

# Constants for the app to run
class SiteConfig:
    APP_CWD = Path(__file__).parent
    SCORES = APP_CWD / "app/scores"
    
# Constants for Flask to run
class FlaskConfig:
    SECRET_KEY = token_urlsafe()[:32]
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024 # 1MB
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{SiteConfig.APP_CWD}/users.db"
    WTF_CSRF_ENABLED = False


