# Officine Talents — API

API FastAPI + MongoDB, réservée à la pharmacie d'officine en Algérie.
Branche autorisée : `maintenance/officine-v2-clean`. Ne jamais modifier `main`.

## Démarrage local sans données réelles

Python 3.12, MongoDB 7 local isolé sur le port 27018 et base `officine_test_demo`.
Ne jamais réutiliser un URI, un export ou une sauvegarde de production dans les tests.

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
# Lancer MongoDB local isolé, si aucun serveur de test n'existe :
docker run -d --name officine-test-mongo -p 127.0.0.1:27018:27017 mongo:7
cp .env.example .env
# Générer SESSION_SECRET puis remplacer le marqueur dans .env :
.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))'
```

Démarrer ensuite :

```sh
.venv/bin/python scripts/seed_demo.py
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

Le script de démonstration exige les variables locales explicites ; charger les valeurs
APP_ENV, MONGODB_URI, MONGODB_DB, SESSION_SECRET, etc. avant son lancement.
`main.py` charge `.env` sans remplacer les variables déjà définies.
Le script n'efface aucune collection. Les profils et offres sont tous fictifs.

## Tests exécutables

```sh
.venv/bin/pytest -q
.venv/bin/ruff check main.py locations.py scripts tests
```

Pytest impose l'URI littéral `mongodb://127.0.0.1:27018`, crée une base
`officine_test_pytest_<aléatoire>` et n'efface que ses propres collections de test.
Les comptes et fichiers utilisés sont fictifs. Les tests de bout en bout sont dans
le dépôt frontend. `scripts/reset_browser_fixtures.py` réinitialise exclusivement
les données fictives de `officine_test_demo`, jamais une base configurable.

## Sécurité

Sessions signées, cookie HttpOnly, contrôle CSRF et d'origine, expiration et révocation
serveur, mots de passe PBKDF2 avec sel ; compatibilité des anciens hash conservée.
Rôles et propriété des ressources vérifiés par l'API. Les admins ne peuvent pas
s'inscrire publiquement et doivent fournir un code TOTP à chaque connexion.
`python scripts/create_admin.py` crée explicitement un admin avec confirmation TOTP.

Les officines doivent être contrôlées par un administrateur avant publication et
consultation des talents. Les profils sont masqués par défaut. Les CV sont privés,
limités à 2 Mo, PDF uniquement, et analysés par ClamAV hors développement/test.
Les liens email sont personnels, expirent en 30 minutes, à usage unique et enregistrés
sous forme hachée. Les limitations de tentatives sont partagées via MongoDB.
La boîte `mail_outbox` n'est autorisée que dans les environnements de test/développement.

La fermeture de compte désactive l'accès, masque le profil et clôture les offres.
L'effacement définitif n'est pas automatisé : une demande administrative est enregistrée,
conformément à la consigne de ne supprimer aucune donnée réelle.

## Déploiement

Voir [DEPLOYMENT.md](DEPLOYMENT.md). Le Dockerfile utilise un utilisateur sans privilèges.
Les secrets et les bases doivent être séparés entre test, préproduction et production.
Aucune commande de déploiement en production n'est exécutée automatiquement.
