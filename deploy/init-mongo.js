// Création initiale uniquement. Aucun effacement, aucune migration d'une base existante.
const database = db.getSiblingDB('officine_staging');
const password = process.env.STAGING_DB_PASSWORD;
if (!password) throw new Error('STAGING_DB_PASSWORD requis pour initialiser le compte applicatif');
database.createUser({user:'officine_app',pwd:password,roles:[{role:'readWrite',db:'officine_staging'}]});
