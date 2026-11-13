# Préproduction et procédure d'ouverture

## État et limites

Le code et les images Docker peuvent être testés localement. La préproduction hébergée
n'est pas publiée : aucun domaine, service SMTP réel ni secret d'exploitation n'a été
fourni. Les emails sont testés avec une boîte fictive, et les tests antivirus locaux
portent sur les refus de PDF actifs ; une validation complète avec ClamAV et SMTP
réels est obligatoire avant ouverture. Aucune base réelle n'a été consultée ou modifiée.

## Installation de préproduction

1. Cloner les deux dépôts côte à côte, sur `maintenance/officine-v2-clean`, et relever
   leurs identifiants de commit. Ne pas utiliser `main` ni un déploiement automatique.
2. Copier `deploy/staging.env.example` dans un fichier privé hors de Git, accès 0600.
   Générer des secrets aléatoires distincts pour MongoDB root, MongoDB applicatif et
   SESSION_SECRET. Encoder le mot de passe applicatif dans l'URI MongoDB.
3. Choisir un domaine HTTPS dédié et un service SMTP STARTTLS. Configurer les DNS
   SPF, DKIM et DMARC du domaine expéditeur. Renseigner les valeurs réelles dans le
   fichier privé. Ne jamais saisir les secrets dans un ticket ou un dépôt.
4. Lancer sur le serveur prévu :

   ```sh
   docker compose --env-file /chemin/prive/staging.env -f compose.staging.yml config --quiet
   docker compose --env-file /chemin/prive/staging.env -f compose.staging.yml up -d --build
   ```

   MongoDB n'expose aucun port. L'API utilise le compte `officine_app`, limité à
   `officine_staging`. Le compte root ne sert qu'à l'initialisation et aux opérations
   d'exploitation. Le frontend écoute seulement sur 127.0.0.1:8090 du serveur.
5. Configurer un reverse proxy HTTPS externe vers 127.0.0.1:8090 ; rediriger HTTP vers
   HTTPS, ajouter HSTS, limiter les corps à 3 Mo et appliquer une limite de requêtes
   par IP avant le proxy applicatif. L'API ignore les en-têtes X-Forwarded-For non fiables.
   Derrière Nginx, sa limite interne protège globalement le service ; le proxy externe
   doit aussi porter les limites par client. Restreindre `/docs` et `/openapi.json` si exposés.
6. Attendre que MongoDB et ClamAV soient prêts (signatures antivirus téléchargées).
   Vérifier `/health`, puis créer l'administrateur avec `scripts/create_admin.py`
   dans un conteneur temporaire ayant la même configuration privée. Ce script n'est
   pas inclus dans l'image d'exécution : monter uniquement le script en lecture seule
   sous `/app/scripts/create_admin.py`, exécuter avec `/app` dans PYTHONPATH.
7. Créer uniquement des comptes fictifs en préproduction. Exécuter les parcours :
   inscription, email réellement reçu, confirmation, récupération, changement de mot
   de passe et invalidation des anciennes sessions, CV valide et fichier EICAR refusé,
   profil officine, validation TOTP, publication, candidature, messages et fermeture.
   Tester aussi le refus d'accès entre deux candidats et deux recruteurs indépendants.

Dans le cloud Codex, les builds réseau peuvent nécessiter la CA de la session :
`docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt ...`.
Ne jamais désactiver la vérification TLS. La CA de session n'est pas incluse dans les images.

## Base existante et conservation

Aucune migration destructive n'est fournie. Les index uniques peuvent refuser de se
créer si des doublons historiques existent : arrêter la mise en service et produire
un inventaire sans supprimer de document. Les anciens comptes, profils et offres hors
périmètre ne sont pas effacés. Les annonces publiques sont filtrées par secteur et métier.
Les anciens profils devront être rapprochés de leur propriétaire après audit explicite.
Ne jamais copier les données personnelles de production dans les tests.

Avant toute mise en service sur une base existante : sauvegarde chiffrée, restauration
sur une instance isolée autorisée, audit des doublons et du rattachement utilisateurs,
plan de migration réversible et accord explicite. Utiliser un utilisateur MongoDB
limité à la seule base, des connexions TLS, un réseau privé et le chiffrement des volumes.
Les CV et secrets TOTP nécessitent les mêmes protections et restrictions d'accès.

## Effacement et obligations légales

Les demandes de fermeture sont visibles dans l'administration. Le compte est désactivé
immédiatement. Le traitement définitif doit être réalisé par un opérateur habilité selon
une politique de conservation validée ; aucun bouton de purge n'est fourni.
Avant ouverture publique, compléter l'identité de l'exploitant, le contact pour les droits,
les durées de conservation, l'hébergeur et les formalités applicables en Algérie.
La page juridique actuelle indique explicitement les éléments restant à valider.

## Validation puis production, uniquement après autorisation

- Archiver les rapports de tests et les deux identifiants de commit validés.
- Vérifier SMTP réel, ClamAV réel, TLS, sauvegarde/restauration, alertes et permissions.
- Définir la supervision : disponibilité /health, erreurs 5xx, livraison email,
  expiration du certificat, signatures antivirus et capacité disque MongoDB.
- Ne pas journaliser les mots de passe, cookies, liens email, CV ou corps des messages.
- Séparer complètement la base, les identités SMTP, domaines et secrets de production.
- Obtenir l'autorisation du propriétaire avant de publier en production.
- Déployer les images exactes issues des commits validés ; conserver les images précédentes.

Retour arrière : remettre les images antérieures et la configuration correspondante.
Les ajouts de collections sont conservés ; aucune suppression ni restauration écrasant
la base réelle ne doit être déclenchée automatiquement. Un changement de SESSION_SECRET
invalide toutes les sessions et impose une reconnexion. Vérifier les anciens hash lors
d'une répétition contrôlée de migration sans modifier les mots de passe réels.
