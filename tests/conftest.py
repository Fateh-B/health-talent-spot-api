"""Tests exclusivement sur un serveur MongoDB local et une base aléatoire dédiée."""

import os
import sys
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.update(
    APP_ENV="test",
    MONGODB_URI="mongodb://127.0.0.1:27018",
    MONGODB_DB="officine_test_pytest_" + secrets.token_hex(6),
    SESSION_SECRET=secrets.token_hex(32),
    COOKIE_SECURE="false",
    COOKIE_SAMESITE="lax",
    FRONTEND_ORIGINS="http://localhost:8080",
    MAIL_MODE="local",
)
import pytest
from fastapi.testclient import TestClient
import main


@pytest.fixture(autouse=True)
def clean_test_db():
    assert main.db.name.startswith("officine_test_pytest_")
    for name in main.db.list_collection_names():
        main.db[name].delete_many({})
    main.ensure_indexes()


@pytest.fixture
def client():
    with TestClient(main.app, headers={"Origin": "http://localhost:8080"}) as c:
        yield c


@pytest.fixture
def register(client):
    def create(role="CANDIDATE", email="candidate@example.test", verified=True):
        result = client.post(
            "/api/auth/signup",
            json={
                "email": email,
                "password": "FictifPassword42!",
                "role": role,
                "name": "Compte Fictif",
            },
        )
        assert result.status_code == 201, result.text
        data = result.json()
        client.headers["X-CSRF-Token"] = data["csrfToken"]
        if verified:
            main.db.users.update_one(
                {"email": email}, {"$set": {"emailVerified": True}}
            )
        return data["user"]

    return create
