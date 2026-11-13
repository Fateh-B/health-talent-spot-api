# Validation — 13 novembre 2026

Branche : `maintenance/officine-v2-clean`, dans les deux dépôts.

## Résultats effectivement exécutés

- MongoDB 7 réel dans un conteneur local, port 127.0.0.1:27018.
- 17 tests API réussis : parcours complet candidat/recruteur, droits entre comptes,
  CSRF/origine, révocation, emails et tokens expirés/à usage unique, mot de passe,
  suspension/désactivation non destructive, TOTP administrateur, CV PDF et contenu actif,
  unicité des candidatures, métiers et wilayas autorisés, droits de réouverture d'offres.
- 7 tests Chromium de bout en bout réussis : profil, favori, candidature et message ;
  réponse/statut et gestion d'offre ; inscription ; navigation mobile sans débordement ;
  vérification et récupération de mot de passe jusqu'à reconnexion ; administration
  avec TOTP, validation d'officine et publication par le recruteur ; dépôt/téléchargement CV.
- TypeScript, ESLint et construction frontend réussis.
- Ruff API réussi ; compilation Python vérifiée.
- Audits npm et pip-audit : aucune vulnérabilité connue signalée sur les versions testées.
- Images Docker frontend et API construites avec succès.
- Démarrage local des conteneurs Nginx + API + MongoDB : /health et /api/joboffers
  répondent correctement via le même domaine local ; en-têtes de sécurité présents.
- Configuration Compose de préproduction validée syntaxiquement.

## Protection des données

Aucune connexion à MongoDB de production, aucune suppression de données réelles,
aucun export de données personnelles et aucune migration de production.
Les suppressions de préparation des tests sont limitées à des bases et comptes fictifs
locaux explicitement nommés. Les branches main ne sont pas utilisées pour développer.

## Points restant à valider avant ouverture publique

- Domaine de préproduction, TLS, livraison SMTP réelle et DNS expéditeur.
- ClamAV réel en préproduction, signatures et test EICAR ; les PDF actifs sont testés localement.
- MongoDB d'exploitation : droits réseau, chiffrement, sauvegarde/restauration et audit
  des anciens enregistrements. L'absence de données réelles ici interdit de conclure
  à la compatibilité de toutes les anciennes données sans cette validation.
- Identité de l'exploitant, contact confidentialité, durées de conservation et mentions légales.
- Traitement administratif de l'effacement définitif : la désactivation et la demande
  sont implémentées ; aucune purge automatique de données réelles n'est prévue.
- Le navigateur partagé Codex est indisponible dans cette session ; la prévisualisation
  a été rendue et inspectée avec Chromium/Playwright. Le serveur local reste sur :8080.

Aucun déploiement en production n'a été exécuté. Voir DEPLOYMENT.md pour la procédure.
