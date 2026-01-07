from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # The URL prefix for our API endpoints (e.g., /api/v1/login).
    # Good for versioning your API in the future.
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Secure Auth API"

    # CRITICAL: The secret key used to sign and verify JWT tokens.
    # Must be kept secret to prevent attackers from forging tokens.
    SECRET_KEY: str

    # The connection string for the PostgreSQL database.
    DATABASE_URL: str

    # Configuration to load settings from a .env file automatically.
    # env_ignore_empty=True prevents errors if the file has empty lines.
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)


# Create a single instance of Settings to be imported in other files.
settings = Settings()
