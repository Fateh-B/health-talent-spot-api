import hashlib
from io import BytesIO
from urllib.parse import urlparse, parse_qs
from bson import ObjectId
from pypdf import PdfWriter
import pyotp
import main

JOB = {
    "title": "Préparateur en pharmacie",
    "location": "Alger",
    "commune": "Kouba",
    "contractType": "CDI",
    "salary": 65000,
    "description": "Accueil et conseil des clients en pharmacie, gestion des stocks et suivi des commandes.",
}
PROFILE = {
    "name": "Candidat Fictif",
    "title": "Préparateur en pharmacie",
    "location": "Alger",
    "visible": True,
    "skills": ["Conseil"],
}


def login_as(client, email, role):
    r = client.post(
        "/api/auth/login",
        json={"email": email, "password": "FictifPassword42!", "role": role},
    )
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrfToken"]


def pharmacy(client, register):
    user = register("RECRUITER", "pharmacie@example.test")
    r = client.put(
        "/api/my/pharmacy",
        json={
            "name": "Pharmacie Fictive",
            "location": "Alger",
            "commune": "Kouba",
            "address": "10 rue fictive",
            "phone": "0555000000",
            "registrationNumber": "TEST-42",
        },
    )
    assert r.status_code == 200, r.text
    main.db.pharmacies.update_one(
        {"userId": ObjectId(user["id"])}, {"$set": {"approved": True}}
    )
    r = client.post("/api/joboffers", json=JOB)
    assert r.status_code == 201, r.text
    return user, r.json()


def test_full_recruitment_and_private_messages(client, register):
    recruiter, job = pharmacy(client, register)
    candidate = register()
    assert (
        client.put("/api/candidates/" + candidate["id"], json=PROFILE).status_code
        == 200
    )
    assert client.post("/api/jobs/" + job["id"] + "/save").status_code == 200
    assert len(client.get("/api/my/saved").json()) == 1
    app = client.post(
        "/api/jobs/" + job["id"] + "/apply", json={"message": "Candidature fictive"}
    )
    assert app.status_code == 201, app.text
    app = app.json()
    assert client.post("/api/jobs/" + job["id"] + "/apply", json={}).status_code == 409
    assert (
        client.post(
            "/api/applications/" + app["id"] + "/messages", json={"body": "Bonjour"}
        ).status_code
        == 201
    )
    login_as(client, "pharmacie@example.test", "RECRUITER")
    assert len(client.get("/api/recruiter/applications").json()) == 1
    assert client.get("/api/candidates/" + candidate["id"]).status_code == 200
    assert (
        client.patch(
            "/api/applications/" + app["id"] + "/status", json={"status": "ENTRETIEN"}
        ).status_code
        == 200
    )
    assert len(client.get("/api/applications/" + app["id"] + "/messages").json()) == 1
    assert (
        client.post(
            "/api/applications/" + app["id"] + "/messages",
            json={"body": "Entretien proposé"},
        ).status_code
        == 201
    )
    stranger = register(email="stranger@example.test")
    assert stranger["id"] != candidate["id"]
    assert client.get("/api/applications/" + app["id"] + "/messages").status_code == 404
    assert (
        client.patch(
            "/api/applications/" + app["id"] + "/status", json={"status": "ACCEPTEE"}
        ).status_code
        == 403
    )
    login_as(client, "candidate@example.test", "CANDIDATE")
    assert client.get("/api/my/applications").json()[0]["status"] == "ENTRETIEN"
    assert len(client.get("/api/my/notifications").json()) == 2
    assert client.patch("/api/my/notifications/read").status_code == 200
    assert all(n["read"] for n in client.get("/api/my/notifications").json())
    assert client.delete("/api/jobs/" + job["id"] + "/save").status_code == 200
    assert not client.get("/api/my/saved").json()


def test_session_csrf_origin_and_logout_revocation(client, register):
    user = register()
    cookie = client.cookies.get(main.COOKIE)
    client.headers.pop("X-CSRF-Token")
    assert client.put("/api/candidates/" + user["id"], json=PROFILE).status_code == 403
    login_as(client, "candidate@example.test", "CANDIDATE")
    assert (
        client.post(
            "/api/auth/logout", headers={"Origin": "https://attacker.test"}
        ).status_code
        == 403
    )
    cookie = client.cookies.get(main.COOKIE)
    assert client.post("/api/auth/logout").status_code == 200
    client.cookies.set(main.COOKIE, cookie)
    assert client.get("/api/auth/me").status_code == 401


def test_cross_profile_and_role_escalation(client, register):
    u = register()
    assert (
        client.put("/api/candidates/" + str(ObjectId()), json=PROFILE).status_code
        == 403
    )
    assert client.post("/api/joboffers", json=JOB).status_code == 403
    assert client.get("/api/admin/overview").status_code == 403
    assert (
        client.post(
            "/api/auth/signup",
            json={
                "email": "admin@example.test",
                "password": "LongPassword42",
                "role": "ADMIN",
                "name": "Attacker",
            },
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/candidates/" + u["id"], json={**PROFILE, "role": "ADMIN"}
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/candidates/" + u["id"], json={**PROFILE, "title": "Médecin"}
        ).status_code
        == 422
    )


def test_unverified_recruiter_and_officine_approval(client, register):
    register("RECRUITER", "pharmacie@example.test", verified=False)
    assert client.post("/api/joboffers", json=JOB).status_code == 403
    main.db.users.update_one(
        {"email": "pharmacie@example.test"}, {"$set": {"emailVerified": True}}
    )
    assert client.post("/api/joboffers", json=JOB).status_code == 403
    assert client.get("/api/candidates").status_code == 403


def test_email_verification_and_reset_revoke_sessions(client, register):
    register(verified=False)
    url = main.db.mail_outbox.find_one()["url"]
    token = parse_qs(urlparse(url).query)["token"][0]
    assert (
        client.post("/api/auth/verify-email", json={"token": token}).status_code == 200
    )
    assert (
        client.post("/api/auth/verify-email", json={"token": token}).status_code == 400
    )
    assert client.get("/api/auth/me").json()["user"]["emailVerified"]
    assert (
        client.post(
            "/api/auth/forgot-password", json={"email": "candidate@example.test"}
        ).status_code
        == 200
    )
    url = list(main.db.mail_outbox.find())[-1]["url"]
    token = parse_qs(urlparse(url).query)["token"][0]
    r = client.post(
        "/api/auth/reset-password", json={"token": token, "password": "NewPassword42!"}
    )
    assert r.status_code == 200, r.text
    assert client.get("/api/auth/me").status_code == 401
    assert (
        client.post(
            "/api/auth/reset-password",
            json={"token": token, "password": "NewPassword42!"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/auth/login",
            json={
                "email": "candidate@example.test",
                "password": "NewPassword42!",
                "role": "CANDIDATE",
            },
        ).status_code
        == 200
    )


def test_deactivation_without_destructive_deletion(client, register):
    user = register()
    client.put("/api/candidates/" + user["id"], json=PROFILE)
    assert (
        client.post(
            "/api/account/deletion-request", json={"password": "wrong"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/account/deletion-request", json={"password": "FictifPassword42!"}
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me").status_code == 401
    stored = main.db.users.find_one({"_id": ObjectId(user["id"])})
    assert stored and stored["disabled"] and stored["deletionRequestedAt"]
    assert not main.db.candidates.find_one({"userId": ObjectId(user["id"])})["visible"]


def test_pdf_upload_and_access_control(client, register):
    user = register()
    assert (
        client.post(
            "/api/my/cv", files={"file": ("cv.html", b"<script>", "application/pdf")}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/my/cv",
            files={
                "file": (
                    "cv.pdf",
                    b"%PDF-" + b"a" * (2 * 1024 * 1024),
                    "application/pdf",
                )
            },
        ).status_code
        == 413
    )
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    stream = BytesIO()
    writer.write(stream)
    assert (
        client.post(
            "/api/my/cv",
            files={"file": ("cv.pdf", stream.getvalue(), "application/pdf")},
        ).status_code
        == 200
    )
    assert client.get("/api/candidates/" + user["id"] + "/cv").status_code == 200
    register(email="stranger@example.test")
    assert client.get("/api/candidates/" + user["id"] + "/cv").status_code == 403


def test_offer_ownership_edit_and_close(client, register):
    user, job = pharmacy(client, register)
    assert (
        client.put(
            "/api/my/jobs/" + job["id"], json={**JOB, "salary": 70000}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/my/jobs/" + job["id"] + "/status", json={"status": "CLOSED"}
        ).status_code
        == 200
    )
    assert not client.get("/api/joboffers").json()
    register("RECRUITER", "other@example.test")
    assert (
        client.patch(
            "/api/my/jobs/" + job["id"] + "/status", json={"status": "OPEN"}
        ).status_code
        == 404
    )
    assert client.put("/api/my/jobs/" + job["id"], json=JOB).status_code == 403


def test_admin_mfa_and_audit(client, register):
    recruiter = register("RECRUITER", "pharmacie@example.test")
    client.put(
        "/api/my/pharmacy",
        json={
            "name": "Test Officine",
            "location": "Alger",
            "commune": "Kouba",
            "address": "rue fictive",
            "phone": "0555000000",
            "registrationNumber": "TEST",
        },
    )
    secret = pyotp.random_base32()
    admin = main.db.users.insert_one(
        {
            "name": "Admin Test",
            "email": "admin@example.test",
            "role": "ADMIN",
            "passwordHash": main.v2_hash("FictifPassword42!"),
            "totpSecret": secret,
            "emailVerified": True,
        }
    ).inserted_id
    payload = {
        "email": "admin@example.test",
        "password": "FictifPassword42!",
        "role": "ADMIN",
    }
    assert client.post("/api/auth/login", json=payload).status_code == 401
    r = client.post(
        "/api/auth/login", json={**payload, "otp": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrfToken"]
    assert client.get("/api/admin/overview").status_code == 200
    assert (
        client.patch(
            "/api/admin/pharmacies/" + recruiter["id"], json={"approved": True}
        ).status_code
        == 200
    )
    assert main.db.audit.count_documents({"action": "pharmacy.approval"}) == 1
    assert (
        client.patch(
            "/api/admin/users/" + str(admin), json={"disabled": True}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            "/api/admin/users/" + recruiter["id"], json={"disabled": True}
        ).status_code
        == 200
    )


def test_legacy_password_compatibility():
    salt = "0123456789abcdef"
    digest = hashlib.pbkdf2_hmac(
        "sha256", b"LegacyPassword", salt.encode(), 100000
    ).hex()
    assert main.verify_password("LegacyPassword", salt + ":" + digest)
    assert not main.verify_password("wrong", salt + ":" + digest)


def test_auth_rate_limit_and_invalid_identifiers(client):
    payload = {"email": "absent@example.test", "password": "wrong", "role": "CANDIDATE"}
    for _ in range(20):
        assert client.post("/api/auth/login", json=payload).status_code == 401
    assert client.post("/api/auth/login", json=payload).status_code == 429
    assert client.get("/api/joboffers/not-an-id").status_code == 404
    assert (
        client.post(
            "/api/auth/signup",
            json={
                "email": {"$ne": None},
                "password": "LongPassword42",
                "role": "CANDIDATE",
                "name": "Test",
            },
        ).status_code
        == 422
    )


def test_change_password_revokes_all_sessions(client, register):
    register()
    assert (
        client.put(
            "/api/account/password",
            json={"currentPassword": "wrong", "newPassword": "NewPassword42"},
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/account/password",
            json={
                "currentPassword": "FictifPassword42!",
                "newPassword": "NewPassword42",
            },
        ).status_code
        == 200
    )
    assert client.get("/api/auth/me").status_code == 401


def test_location_and_whitespace_validation(client, register):
    user = register()
    assert (
        client.put(
            "/api/candidates/" + user["id"], json={**PROFILE, "location": "Paris"}
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/candidates/" + user["id"], json={**PROFILE, "name": "   "}
        ).status_code
        == 422
    )


def test_expired_token_and_generic_forgot_response(client, register):
    from datetime import timedelta

    register()
    raw = "expired-token-for-a-fictitious-account"
    main.db.tokens.insert_one(
        {
            "digest": hashlib.sha256(raw.encode()).hexdigest(),
            "userId": ObjectId(),
            "purpose": "reset",
            "expiresAt": main.utcnow() - timedelta(seconds=1),
        }
    )
    assert (
        client.post(
            "/api/auth/reset-password", json={"token": raw, "password": "NewPassword42"}
        ).status_code
        == 400
    )
    a = client.post("/api/auth/forgot-password", json={"email": "absent@example.test"})
    b = client.post(
        "/api/auth/forgot-password", json={"email": "candidate@example.test"}
    )
    assert a.json() == b.json()


def test_pdf_active_content_rejected(client, register):
    register()
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer._root_object[NameObject("/OpenAction")] = DictionaryObject(
        {
            NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject('app.alert("example")'),
        }
    )
    stream = BytesIO()
    writer.write(stream)
    assert (
        client.post(
            "/api/my/cv",
            files={"file": ("cv.pdf", stream.getvalue(), "application/pdf")},
        ).status_code
        == 422
    )


def test_revoked_pharmacy_cannot_reopen_offers(client, register):
    recruiter, job = pharmacy(client, register)
    main.db.pharmacies.update_one(
        {"userId": ObjectId(recruiter["id"])}, {"$set": {"approved": False}}
    )
    assert (
        client.patch(
            "/api/my/jobs/" + job["id"] + "/status", json={"status": "CLOSED"}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/my/jobs/" + job["id"] + "/status", json={"status": "OPEN"}
        ).status_code
        == 403
    )


def test_pharmacy_changes_require_reapproval_and_close_existing_jobs(client, register):
    _, job = pharmacy(client, register)
    r = client.put(
        "/api/my/pharmacy",
        json={
            "name": "Officine Modifiée Fictive",
            "location": "Alger",
            "commune": "Kouba",
            "address": "Nouvelle adresse fictive",
            "phone": "0555000000",
            "registrationNumber": "TEST-42",
        },
    )
    assert r.status_code == 200
    assert not r.json()["approved"]
    assert (
        main.db.joboffers.find_one({"_id": ObjectId(job["id"])})["status"] == "CLOSED"
    )
    assert (
        client.patch(
            "/api/my/jobs/" + job["id"] + "/status", json={"status": "OPEN"}
        ).status_code
        == 403
    )
