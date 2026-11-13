"""Réinitialisation exclusivement des comptes fictifs de la démonstration locale."""

import hashlib
import secrets
from pymongo import MongoClient

# Serveur et base sont littéraux : aucune URI issue de la configuration de production.
db = MongoClient("mongodb://127.0.0.1:27018")["officine_test_demo"]
users = list(
    db.users.find(
        {"email": {"$in": ["candidat@example.test", "officine@example.test"]}}
    )
)
assert len(users) == 2 and all(u["email"].endswith("@example.test") for u in users)
ids = [u["_id"] for u in users]
applications = list(db.applications.find({"candidateId": {"$in": ids}}))
db.messages.delete_many({"applicationId": {"$in": [a["_id"] for a in applications]}})
db.applications.delete_many({"candidateId": {"$in": ids}})
db.saved_jobs.delete_many({"candidateId": {"$in": ids}})
db.notifications.delete_many({"recipientId": {"$in": ids}})
db.rate_limits.delete_many({})
db.joboffers.update_many(
    {"recruiterId": {"$in": ids}}, {"$set": {"applicants": 0, "status": "OPEN"}}
)

# Administrateur fictif pour les tests navigateur, sans aucune modification hors base test.

salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", b"DemoOfficine42!", salt, 310000)
db.users.update_one(
    {"email": "admin@example.test"},
    {
        "$set": {
            "name": "Admin Fictif",
            "role": "ADMIN",
            "passwordHash": "v2$" + salt.hex() + "$" + digest.hex(),
            "totpSecret": "JBSWY3DPEHPK3PXP",
            "emailVerified": True,
        },
        "$unset": {"lastTotpStep": ""},
    },
    upsert=True,
)

db.users.update_one(
    {"email": "validation@example.test"},
    {
        "$set": {
            "name": "Pharmacie Validation Fictive",
            "role": "RECRUITER",
            "passwordHash": "v2$" + salt.hex() + "$" + digest.hex(),
            "emailVerified": True,
        }
    },
    upsert=True,
)
pending = db.users.find_one({"email": "validation@example.test"})
db.pharmacies.update_one(
    {"userId": pending["_id"]},
    {
        "$set": {
            "name": "Pharmacie Validation Fictive",
            "location": "Alger",
            "commune": "Kouba",
            "address": "10 rue fictive",
            "phone": "0555000000",
            "registrationNumber": "FICTIF-VALIDATION",
            "approved": False,
        }
    },
    upsert=True,
)
db.joboffers.update_many(
    {"recruiterId": pending["_id"]}, {"$set": {"status": "CLOSED"}}
)
