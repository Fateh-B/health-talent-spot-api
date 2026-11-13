"""Provisionnement explicite d'un administrateur, jamais via inscription publique."""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pyotp
import main

email = main.normalized_email(input("Email administrateur : "))
password = getpass.getpass("Mot de passe (16 caractères minimum) : ")
if len(password) < 16:
    raise SystemExit("Mot de passe trop court")
if main.db.users.find_one({"email": email}):
    raise SystemExit("Compte déjà existant : aucune modification effectuée")
secret = pyotp.random_base32()
print("Ajouter ce secret dans votre application TOTP (ne pas partager) :", secret)
if not pyotp.TOTP(secret).verify(input("Code de confirmation TOTP : ")):
    raise SystemExit("Code invalide, aucun compte créé")
main.db.users.insert_one(
    {
        "email": email,
        "name": "Administration",
        "role": "ADMIN",
        "passwordHash": main.v2_hash(password),
        "totpSecret": secret,
        "emailVerified": True,
        "createdAt": main.utcnow(),
    }
)
print("Administrateur créé.")
