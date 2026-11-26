"""Central configuration placeholder. Load secrets from environment variables."""
import os

SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///instance/atlas.db")
