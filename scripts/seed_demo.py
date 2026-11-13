"""Données fictives locales uniquement. N'efface jamais de collection."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if (
    os.environ.get("APP_ENV") not in ("test", "development")
    or not os.environ.get("MONGODB_DB", "").startswith("officine_test")
    or os.environ.get("MONGODB_URI") != "mongodb://127.0.0.1:27018"
):
    raise SystemExit(
        "Seed autorisé uniquement sur MongoDB local :27018 et officine_test*"
    )
import main

main.ensure_indexes()
for email, role, name in [
    ("candidat@example.test", "CANDIDATE", "Amel — démonstration"),
    ("officine@example.test", "RECRUITER", "Pharmacie — démonstration"),
]:
    main.db.users.update_one(
        {"email": email},
        {
            "$setOnInsert": {
                "name": name,
                "role": role,
                "passwordHash": main.v2_hash("DemoOfficine42!"),
                "emailVerified": True,
                "createdAt": main.utcnow(),
            }
        },
        upsert=True,
    )
c = main.db.users.find_one({"email": "candidat@example.test"})
r = main.db.users.find_one({"email": "officine@example.test"})
main.db.candidates.update_one(
    {"userId": c["_id"]},
    {
        "$setOnInsert": {
            "name": c["name"],
            "title": "Préparateur en pharmacie",
            "location": "Alger",
            "commune": "Kouba",
            "about": "Profil fictif de démonstration, aucune personne réelle.",
            "skills": ["Conseil au comptoir", "Gestion des stocks"],
            "visible": True,
            "education": "Formation fictive en préparation pharmaceutique",
            "experience": "3 ans",
            "availability": "Immédiate",
        }
    },
    upsert=True,
)
main.db.pharmacies.update_one(
    {"userId": r["_id"]},
    {
        "$setOnInsert": {
            "name": r["name"],
            "location": "Alger",
            "commune": "Kouba",
            "address": "Adresse fictive de démonstration",
            "phone": "0555000000",
            "registrationNumber": "DEMO-EXEMPLE",
            "approved": True,
            "sector": "OFFICINE",
            "country": "DZ",
        }
    },
    upsert=True,
)
for title, location, salary in [
    ("Préparateur en pharmacie", "Alger", 65000),
    ("Pharmacien assistant", "Oran", 90000),
    ("Vendeur en pharmacie", "Constantine", 45000),
]:
    main.db.joboffers.update_one(
        {"recruiterId": r["_id"], "title": title},
        {
            "$setOnInsert": {
                "sector": "OFFICINE",
                "location": location,
                "commune": "Centre",
                "country": "DZ",
                "contractType": "CDI",
                "salary": salary,
                "salaryPeriod": "MOIS",
                "description": "Offre fictive de démonstration. Accueil et conseil en officine, suivi des commandes et gestion des stocks.",
                "requiredSkills": "Conseil, organisation, travail en équipe",
                "experienceLevel": "INTERMEDIAIRE",
                "status": "OPEN",
                "createdAt": main.utcnow(),
                "postedDate": main.utcnow(),
                "applicants": 0,
            }
        },
        upsert=True,
    )
print("Démonstration fictive prête — aucune donnée existante supprimée.")
