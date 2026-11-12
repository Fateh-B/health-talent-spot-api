"""Officine Talents — API sécurisée, uniquement recrutement en pharmacie d'officine."""
import os
import re
import hmac
import base64
import hashlib
import secrets
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="Officine Talents API", version="2.0.0")
ALLOWED_ORIGINS = [x.strip().rstrip("/") for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
db = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=5000)["health_talent_spot"]
ROLES = ("CANDIDATE", "RECRUITER")
TITLES = ("Pharmacien d'officine", "Pharmacien assistant", "Préparateur en pharmacie", "Vendeur en pharmacie")
CONTRACTS = ("CDI", "CDD", "REMPLACEMENT_PONCTUEL")
COOKIE = "officine_session"
# Ne jamais générer une clé éphémère en prod : provoquer explicitement une erreur si absente.
def secret_key():
    secret = os.getenv("SESSION_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "Configuration SESSION_SECRET manquante (32 caractères minimum)")
    return secret.encode()

def utcnow():
    return datetime.now(timezone.utc)

def identifier(value: str):
    if not ObjectId.is_valid(value):
        raise HTTPException(404, "Ressource introuvable")
    return ObjectId(value)

def normalized_email(email: str):
    value = email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value) or len(value) > 254:
        raise HTTPException(422, "Adresse email invalide")
    return value

def password_hash(password: str):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + ":" + digest.hex()

def verify_password(password: str, stored: str):
    try:
        salt, digest = stored.split(":")
        iterations = 100000
        # Compatibilité avec les comptes créés par l'ancienne API (100000 itérations).
        # Les comptes v2 utilisent un préfixe distinct.
        if stored.startswith("v2$"):
            _, salt, digest = stored.split("$")
            iterations = 310000
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations)
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False

def v2_hash(password: str):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "v2$" + salt.hex() + "$" + digest.hex()

def signed_session(user):
    payload = {"sub": str(user["_id"]), "exp": int((utcnow() + timedelta(days=7)).timestamp()), "csrf": secrets.token_urlsafe(24)}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(secret_key(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig, payload["csrf"]

def session_payload(request: Request):
    token = request.cookies.get(COOKIE, "")
    try:
        body, signature = token.split(".")
        expected = hmac.new(secret_key(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Bad signature")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload["exp"] <= int(utcnow().timestamp()):
            raise ValueError("Expired")
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(401, "Connexion requise")

def current_user(request: Request):
    payload = session_payload(request)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin", "").rstrip("/")
        # Origin obligatoire pour les modifications depuis un navigateur.
        if origin not in ALLOWED_ORIGINS or not hmac.compare_digest(
            request.headers.get("x-csrf-token", ""), payload["csrf"]
        ):
            raise HTTPException(403, "Contrôle CSRF invalide")
    user = db.users.find_one({"_id": identifier(payload["sub"])})
    if not user or user.get("role") not in ROLES:
        raise HTTPException(401, "Compte indisponible")
    return user

def role_required(role):
    def check(user=Depends(current_user)):
        if user["role"] != role:
            raise HTTPException(403, "Accès interdit pour ce compte")
        return user
    return check

def public_user(u):
    return {"id": str(u["_id"]), "email": u["email"], "name": u.get("name") or "",
            "role": u["role"], "phone": u.get("phone") or ""}

def serialize(job):
    result = dict(job)
    result["id"] = str(result.pop("_id"))
    for key in ("recruiterId", "candidateId", "jobId", "userId"):
        if isinstance(result.get(key), ObjectId):
            result[key] = str(result[key])
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result

class Signup(BaseModel):
    email: str
    password: str = Field(min_length=10, max_length=128)
    role: Literal["CANDIDATE", "RECRUITER"]
    name: str = Field(min_length=2, max_length=120)
    phone: Optional[str] = Field(default=None, max_length=30)

class Login(BaseModel):
    email: str
    password: str
    role: Literal["CANDIDATE", "RECRUITER"]

class JobInput(BaseModel):
    title: Literal["Pharmacien d'officine", "Pharmacien assistant", "Préparateur en pharmacie", "Vendeur en pharmacie"]
    sector: Literal["OFFICINE"] = "OFFICINE"
    specialty: Optional[str] = None
    location: str = Field(min_length=2, max_length=100)
    contractType: Literal["CDI", "CDD", "REMPLACEMENT_PONCTUEL"]
    salary: int = Field(gt=0, le=10000000)
    salaryPeriod: Literal["MOIS", "JOUR", "HEURE"] = "MOIS"
    experienceLevel: str = "DEBUTANT"
    genderPreference: str = "HOMME_OU_FEMME"
    description: str = Field(min_length=30, max_length=10000)
    requiredSkills: str = ""

class ProfileInput(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)
    title: Optional[str] = Field(default=None, max_length=120)
    location: Optional[str] = Field(default=None, max_length=100)
    experience: Optional[str] = Field(default=None, max_length=120)
    availability: Optional[str] = Field(default=None, max_length=120)
    about: Optional[str] = Field(default=None, max_length=4000)
    skills: Optional[list[str]] = None
    professionalExperiences: Optional[list[dict]] = None
    visible: Optional[bool] = None

class ApplicationInput(BaseModel):
    message: str = Field(default="", max_length=3000)

class StatusInput(BaseModel):
    status: Literal["EN_REVUE", "ENTRETIEN", "ACCEPTEE", "REFUSEE"]

class MessageInput(BaseModel):
    body: str = Field(min_length=1, max_length=3000)

@app.on_event("startup")
def ensure_indexes():
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.applications.create_index([("candidateId", ASCENDING), ("jobId", ASCENDING)], unique=True)
    db.joboffers.create_index([("recruiterId", ASCENDING), ("status", ASCENDING)])
    db.candidates.create_index([("userId", ASCENDING)])
    db.messages.create_index([("applicationId", ASCENDING), ("createdAt", ASCENDING)])
    db.saved_jobs.create_index([("candidateId", ASCENDING), ("jobId", ASCENDING)], unique=True)

def write_cookie(response: Response, token: str, csrf: str):
    response.set_cookie(COOKIE, token, max_age=604800, httponly=True,
                        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
                        samesite=os.getenv("COOKIE_SAMESITE", "none"), path="/")
    # Le CSRF est renvoyé explicitement et reste en mémoire côté front.
    return csrf

@app.post("/api/auth/signup", status_code=201)
def signup(data: Signup, response: Response):
    email = normalized_email(data.email)
    if db.users.find_one({"email": email}):
        raise HTTPException(409, "Adresse email déjà utilisée")
    document = {"email": email, "passwordHash": v2_hash(data.password), "role": data.role,
                "name": data.name.strip(), "phone": data.phone, "createdAt": utcnow()}
    try:
        document["_id"] = db.users.insert_one(document).inserted_id
    except DuplicateKeyError:
        raise HTTPException(409, "Adresse email déjà utilisée")
    token, csrf = signed_session(document)
    write_cookie(response, token, csrf)
    return {"user": public_user(document), "csrfToken": csrf}

@app.post("/api/auth/login")
def login(data: Login, response: Response):
    user = db.users.find_one({"email": normalized_email(data.email)})
    if not user or not verify_password(data.password, user.get("passwordHash", "")) or user["role"] != data.role:
        raise HTTPException(401, "Identifiants incorrects")
    token, csrf = signed_session(user)
    write_cookie(response, token, csrf)
    return {"user": public_user(user), "csrfToken": csrf}

@app.get("/api/auth/me")
def me(request: Request, user=Depends(current_user)):
    return {"user": public_user(user), "csrfToken": session_payload(request)["csrf"]}

@app.post("/api/auth/logout")
def logout(response: Response, user=Depends(current_user)):
    response.delete_cookie(COOKIE, path="/", secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
                           samesite=os.getenv("COOKIE_SAMESITE", "none"))
    return {"ok": True}

@app.get("/api/joboffers")
def get_jobs():
    return [serialize(x) for x in db.joboffers.find({"sector": "OFFICINE", "status": {"$ne": "CLOSED"}}).sort("createdAt", -1).limit(200)]

@app.get("/api/joboffers/{job_id}")
def get_job(job_id: str):
    job = db.joboffers.find_one({"_id": identifier(job_id), "sector": "OFFICINE"})
    if not job:
        raise HTTPException(404, "Offre introuvable")
    return serialize(job)

@app.post("/api/joboffers", status_code=201)
def create_job(data: JobInput, user=Depends(role_required("RECRUITER"))):
    now = utcnow()
    doc = data.model_dump()
    doc.update({"recruiterId": user["_id"], "postedDate": now, "createdAt": now, "updatedAt": now,
                "experience": doc["experienceLevel"], "applicants": 0, "rating": 0, "status": "OPEN"})
    doc["_id"] = db.joboffers.insert_one(doc).inserted_id
    return serialize(doc)

@app.get("/api/my/jobs")
def own_jobs(user=Depends(role_required("RECRUITER"))):
    return [serialize(x) for x in db.joboffers.find({"recruiterId": user["_id"]}).sort("createdAt", -1)]

@app.patch("/api/my/jobs/{job_id}/status")
def close_job(job_id: str, data: dict, user=Depends(role_required("RECRUITER"))):
    if data.get("status") not in ("OPEN", "CLOSED"):
        raise HTTPException(422, "Statut invalide")
    updated = db.joboffers.find_one_and_update(
        {"_id": identifier(job_id), "recruiterId": user["_id"]},
        {"$set": {"status": data["status"], "updatedAt": utcnow()}}, return_document=True)
    if not updated:
        raise HTTPException(404, "Offre introuvable")
    return serialize(updated)

@app.get("/api/candidates")
def candidates(user=Depends(role_required("RECRUITER"))):
    profiles = db.candidates.find({"visible": True}).limit(100)
    return [serialize(p) for p in profiles]

@app.get("/api/candidates/{candidate_id}")
def candidate_detail(candidate_id: str, user=Depends(current_user)):
    target = identifier(candidate_id)
    if user["role"] == "CANDIDATE" and user["_id"] != target:
        raise HTTPException(403, "Accès interdit")
    query = {"userId": target} if user["role"] == "CANDIDATE" else {"$or": [{"userId": target}, {"_id": target}]}
    profile = db.candidates.find_one(query)
    if not profile or (user["role"] == "RECRUITER" and not profile.get("visible")):
        raise HTTPException(404, "Profil introuvable")
    return serialize(profile)

@app.put("/api/candidates/{candidate_id}")
def update_candidate(candidate_id: str, data: ProfileInput, user=Depends(role_required("CANDIDATE"))):
    if identifier(candidate_id) != user["_id"]:
        raise HTTPException(403, "Modification d'un autre profil interdite")
    values = data.model_dump(exclude_unset=True)
    if values.get("title") and values["title"] not in TITLES:
        raise HTTPException(422, "Métier hors officine")
    if "professionalExperiences" in values and values["professionalExperiences"] is not None and len(values["professionalExperiences"]) > 20:
        raise HTTPException(422, "Trop d'expériences")
    if "skills" in values and values["skills"] is not None and len(values["skills"]) > 40:
        raise HTTPException(422, "Trop de compétences")
    values["updatedAt"] = utcnow()
    if db.candidates.find_one({"userId": user["_id"]}) is None:
        db.candidates.insert_one({"userId": user["_id"], "createdAt": utcnow(), "visible": False})
    db.candidates.update_one({"userId": user["_id"]}, {"$set": values})
    return serialize(db.candidates.find_one({"userId": user["_id"]}))

@app.post("/api/jobs/{job_id}/apply", status_code=201)
def apply(job_id: str, data: ApplicationInput, user=Depends(role_required("CANDIDATE"))):
    job = db.joboffers.find_one({"_id": identifier(job_id), "sector": "OFFICINE", "status": {"$ne": "CLOSED"}})
    if not job:
        raise HTTPException(404, "Offre indisponible")
    doc = {"jobId": job["_id"], "candidateId": user["_id"], "recruiterId": job["recruiterId"],
           "message": data.message, "status": "ENVOYEE", "createdAt": utcnow(), "updatedAt": utcnow()}
    try:
        doc["_id"] = db.applications.insert_one(doc).inserted_id
    except DuplicateKeyError:
        raise HTTPException(409, "Vous avez déjà postulé à cette offre")
    db.joboffers.update_one({"_id": job["_id"]}, {"$inc": {"applicants": 1}})
    return serialize(doc)

@app.get("/api/my/applications")
def my_applications(user=Depends(role_required("CANDIDATE"))):
    result = []
    for a in db.applications.find({"candidateId": user["_id"]}).sort("createdAt", -1):
        doc = serialize(a)
        job = db.joboffers.find_one({"_id": a["jobId"]})
        doc["jobTitle"] = job.get("title") if job else "Offre supprimée"
        result.append(doc)
    return result

@app.get("/api/recruiter/applications")
def recruiter_applications(user=Depends(role_required("RECRUITER"))):
    result = []
    for a in db.applications.find({"recruiterId": user["_id"]}).sort("createdAt", -1):
        doc = serialize(a)
        candidate = db.users.find_one({"_id": a["candidateId"]})
        job = db.joboffers.find_one({"_id": a["jobId"]})
        doc["candidateName"] = candidate.get("name") if candidate else "Candidat"
        doc["jobTitle"] = job.get("title") if job else "Offre"
        result.append(doc)
    return result

@app.patch("/api/applications/{application_id}/status")
def application_status(application_id: str, data: StatusInput, user=Depends(role_required("RECRUITER"))):
    from pymongo import ReturnDocument
    item = db.applications.find_one_and_update({"_id": identifier(application_id), "recruiterId": user["_id"]},
        {"$set": {"status": data.status, "updatedAt": utcnow()}}, return_document=ReturnDocument.AFTER)
    if not item:
        raise HTTPException(404, "Candidature introuvable")
    return serialize(item)

def access_application(application_id: str, user):
    a = db.applications.find_one({"_id": identifier(application_id)})
    if not a or user["_id"] not in (a["candidateId"], a["recruiterId"]):
        raise HTTPException(404, "Candidature introuvable")
    return a

@app.get("/api/applications/{application_id}/messages")
def messages(application_id: str, user=Depends(current_user)):
    a = access_application(application_id, user)
    return [serialize(x) for x in db.messages.find({"applicationId": a["_id"]}).sort("createdAt", 1).limit(500)]

@app.post("/api/applications/{application_id}/messages", status_code=201)
def send_message(application_id: str, data: MessageInput, user=Depends(current_user)):
    a = access_application(application_id, user)
    doc = {"applicationId": a["_id"], "senderId": str(user["_id"]), "body": data.body.strip(), "createdAt": utcnow()}
    if not doc["body"]:
        raise HTTPException(422, "Message vide")
    doc["_id"] = db.messages.insert_one(doc).inserted_id
    return serialize(doc)

@app.get("/api/my/saved")
def saved_jobs(user=Depends(role_required("CANDIDATE"))):
    ids = [x["jobId"] for x in db.saved_jobs.find({"candidateId": user["_id"]})]
    return [serialize(x) for x in db.joboffers.find({"_id": {"$in": ids}, "sector": "OFFICINE"})]

@app.post("/api/jobs/{job_id}/save")
def save_job(job_id: str, user=Depends(role_required("CANDIDATE"))):
    oid = identifier(job_id)
    if not db.joboffers.find_one({"_id": oid, "sector": "OFFICINE"}):
        raise HTTPException(404, "Offre introuvable")
    db.saved_jobs.update_one({"candidateId": user["_id"], "jobId": oid},
                             {"$setOnInsert": {"createdAt": utcnow()}}, upsert=True)
    return {"ok": True}

@app.delete("/api/jobs/{job_id}/save")
def unsave_job(job_id: str, user=Depends(role_required("CANDIDATE"))):
    db.saved_jobs.delete_one({"candidateId": user["_id"], "jobId": identifier(job_id)})
    return {"ok": True}

@app.get("/health")
def health():
    db.command("ping")
    return {"status": "ok"}
