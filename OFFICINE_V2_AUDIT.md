# Officine V2 — sécurité et base de données

Branche de travail isolée créée à partir de `main`; **aucune migration, suppression ou opération sur la base MongoDB réelle**.

## Problèmes constatés dans `main.py`
- Les endpoints `/api/auth/login` et `/api/auth/signup` renvoient un utilisateur mais n'émettent pas de session authentifiée vérifiable.
- `PUT /api/candidates/{candidate_id}` ne vérifie pas l'identité du propriétaire.
- `POST /api/joboffers` est public et fixe `recruiterId = "anonymous"`.
- Les offres et candidats ne sont pas limités au domaine officinal.
- Les comptes, profils et offres sont dans MongoDB; aucun accès aux données de production n'a été effectué lors de cet audit.

## Avant mise en production
1. Définir un modèle de session (cookies HttpOnly Secure SameSite, CSRF si requis) ou tokens signés vérifiés serveur.
2. Vérifier systématiquement les droits candidat/recruteur/admin et la propriété de toute ressource avant écriture/lecture de données privées.
3. Ajouter les validations Pydantic : rôles autorisés, métiers officinaux, listes blanches de types de contrat, champs de localisation, limites.
4. Créer des index MongoDB uniques sur emails normalisés, candidatures `(jobId,candidateId)`, plus index de recherche.
5. Créer collections `applications`, `messages`, `saved_jobs`, statuts et journal d'audit.
6. Ajouter flux de vérification email et de réinitialisation de mot de passe, protection anti-abus et tests d'autorisation.
7. Sauvegarder la base existante et réaliser toute migration avec dry-run, plan de rollback et accord explicite.

## À ne jamais supprimer automatiquement
Collections `users`, `candidates`, `joboffers` et tout document lié à des personnes réelles. Isoler les données anciennes hors périmètre avant toute suppression potentielle.
