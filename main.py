"""Officine Talents — API sécurisée, uniquement recrutement en pharmacie d'officine."""

import os
import re
import hmac
import base64
import hashlib
import secrets
import json
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from contextlib import asynccontextmanager
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from pydantic import BaseModel, Field, ConfigDict, field_validator
from dotenv import load_dotenv

load_dotenv()


@asynccontextmanager
async def lifespan(app):
    ensure_indexes()
    yield


app = FastAPI(title="Officine Talents API", version="2.1.0", lifespan=lifespan)
ALLOWED_ORIGINS = [
    x.strip().rstrip("/")
    for x in os.getenv("FRONTEND_ORIGINS", "http://localhost:5173").split(",")
    if x.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)
DB_NAME = os.getenv("MONGODB_DB", "officine_test")
ENVIRONMENT = os.getenv("APP_ENV", "development")
if ENVIRONMENT not in ("test", "development", "staging", "production"):
    raise RuntimeError("APP_ENV invalide")
if ENVIRONMENT in ("staging", "production") and (
    not os.getenv("MONGODB_URI") or not os.getenv("MONGODB_DB")
):
    raise RuntimeError("MongoDB doit être configuré explicitement hors développement")
if ENVIRONMENT in ("test", "development") and not DB_NAME.startswith("officine_test"):
    raise RuntimeError(
        "Les environnements locaux doivent utiliser une base officine_test dédiée"
    )
if ENVIRONMENT == "staging" and not DB_NAME.startswith("officine_staging"):
    raise RuntimeError(
        "La préproduction doit utiliser une base officine_staging dédiée"
    )
db = MongoClient(
    os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017"),
    serverSelectionTimeoutMS=5000,
)[DB_NAME]
ROLES = ("CANDIDATE", "RECRUITER")
TITLES = (
    "Pharmacien d'officine",
    "Pharmacien assistant",
    "Préparateur en pharmacie",
    "Vendeur en pharmacie",
)
CONTRACTS = ("CDI", "CDD", "REMPLACEMENT_PONCTUEL")
COOKIE = "officine_session"


# Ne jamais générer une clé éphémère en prod : provoquer explicitement une erreur si absente.
def secret_key():
    secret = os.getenv("SESSION_SECRET", "")
    if len(secret) < 32 or secret.startswith(("REPLACE_", "CHANGE_ME")):
        raise HTTPException(
            503, "Configuration SESSION_SECRET manquante (32 caractères minimum)"
        )
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


def verify_password(password: str, stored: str):
    """Accepte les mots de passe v2 et les anciens hash PBKDF2 de l'API initiale."""
    try:
        if stored.startswith("v2$"):
            _, salt, digest = stored.split("$")
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt), 310000
            )
        else:
            salt, digest = stored.split(":")
            # Le code original utilisait les caractères ASCII hexadécimaux
            # du sel, pas les octets résultant de bytes.fromhex().
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 100000
            )
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError, AttributeError):
        return False


def v2_hash(password: str):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return "v2$" + salt.hex() + "$" + digest.hex()


def signed_session(user):
    payload = {
        "sub": str(user["_id"]),
        "exp": int((utcnow() + timedelta(days=7)).timestamp()),
        "csrf": secrets.token_urlsafe(24),
        "sid": secrets.token_urlsafe(32),
        "version": user.get("sessionVersion", 0),
    }
    db.sessions.insert_one(
        {
            "sid": payload["sid"],
            "userId": user["_id"],
            "expiresAt": utcnow() + timedelta(days=7),
        }
    )
    body = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
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
        if not db.sessions.find_one({"sid": payload["sid"]}):
            raise ValueError("Revoked")
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
    if (
        not user
        or user.get("role") not in (*ROLES, "ADMIN")
        or user.get("disabled")
        or payload.get("version") != user.get("sessionVersion", 0)
    ):
        raise HTTPException(401, "Compte indisponible")
    return user


def role_required(role):
    def check(user=Depends(current_user)):
        if user["role"] != role:
            raise HTTPException(403, "Accès interdit pour ce compte")
        return user

    return check


def public_user(u):
    return {
        "id": str(u["_id"]),
        "email": u["email"],
        "name": u.get("name") or "",
        "role": u["role"],
        "phone": u.get("phone") or "",
        "emailVerified": bool(u.get("emailVerified")),
    }


def serialize(job):
    result = dict(job)
    result["id"] = str(result.pop("_id"))
    for key in (
        "recruiterId",
        "candidateId",
        "jobId",
        "userId",
        "applicationId",
        "recipientId",
    ):
        if isinstance(result.get(key), ObjectId):
            result[key] = str(result[key])
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("location", check_fields=False)
    @classmethod
    def algerian_wilaya(cls, value):
        from locations import WILAYAS

        if value is None:
            return value

        def norm(text):
            return "".join(
                c
                for c in unicodedata.normalize(
                    "NFD", text.replace("_", " ").replace("’", "'")
                )
                if not unicodedata.combining(c)
            ).lower()

        choices = {norm(w): w for w in WILAYAS}
        if norm(value.strip()) not in choices:
            raise ValueError("Choisissez une wilaya algérienne")
        return choices[norm(value.strip())]

    @field_validator("name", check_fields=False)
    @classmethod
    def nonempty_name(cls, value):
        if value is not None and len(value.strip()) < 2:
            raise ValueError("Nom trop court")
        return value.strip() if value else value


class Signup(StrictModel):
    email: str
    password: str = Field(min_length=10, max_length=128)
    role: Literal["CANDIDATE", "RECRUITER"]
    name: str = Field(min_length=2, max_length=120)
    phone: Optional[str] = Field(default=None, max_length=30)


class Login(StrictModel):
    email: str
    password: str = Field(min_length=1, max_length=128)
    otp: str = Field(default="", max_length=6)
    role: Literal["CANDIDATE", "RECRUITER", "ADMIN"]


class JobInput(StrictModel):
    title: Literal[
        "Pharmacien d'officine",
        "Pharmacien assistant",
        "Préparateur en pharmacie",
        "Vendeur en pharmacie",
    ]
    sector: Literal["OFFICINE"] = "OFFICINE"
    specialty: Optional[str] = Field(default=None, max_length=100)
    location: str = Field(min_length=2, max_length=100)
    contractType: Literal["CDI", "CDD", "REMPLACEMENT_PONCTUEL"]
    salary: int = Field(gt=0, le=10000000)
    salaryPeriod: Literal["MOIS", "JOUR", "HEURE"] = "MOIS"
    experienceLevel: Literal["DEBUTANT", "INTERMEDIAIRE", "EXPERIMENTE"] = "DEBUTANT"
    genderPreference: Literal["HOMME_OU_FEMME", "HOMME", "FEMME"] = "HOMME_OU_FEMME"
    description: str = Field(min_length=30, max_length=10000)
    requiredSkills: str = Field(default="", max_length=3000)
    commune: str = Field(default="", max_length=100)
    country: Literal["DZ"] = "DZ"


class Experience(StrictModel):
    position: str = Field(max_length=120)
    company: str = Field(max_length=120)
    period: str = Field(max_length=100)
    description: str = Field(default="", max_length=1000)


class ProfileInput(StrictModel):
    name: Optional[str] = Field(default=None, max_length=120)
    title: Optional[str] = Field(default=None, max_length=120)
    location: Optional[str] = Field(default=None, max_length=100)
    experience: Optional[str] = Field(default=None, max_length=120)
    availability: Optional[str] = Field(default=None, max_length=120)
    about: Optional[str] = Field(default=None, max_length=4000)
    skills: Optional[list[str]] = Field(default=None, max_length=40)

    @field_validator("skills")
    @classmethod
    def valid_skills(cls, values):
        if values and any(len(v) > 100 for v in values):
            raise ValueError("Compétence trop longue")
        return values

    professionalExperiences: Optional[list[Experience]] = Field(
        default=None, max_length=20
    )
    education: str = Field(default="", max_length=2000)
    languages: str = Field(default="", max_length=200)
    commune: str = Field(default="", max_length=100)
    phone: str = Field(default="", max_length=30)
    country: Literal["DZ"] = "DZ"
    visible: Optional[bool] = None


class ApplicationInput(BaseModel):
    message: str = Field(default="", max_length=3000)


class StatusInput(BaseModel):
    status: Literal["EN_REVUE", "ENTRETIEN", "ACCEPTEE", "REFUSEE"]


class MessageInput(BaseModel):
    body: str = Field(min_length=1, max_length=3000)


def ensure_indexes():
    secret_key()
    if ENVIRONMENT in ("staging", "production"):
        if os.getenv("COOKIE_SECURE", "true") != "true" or not all(
            o.startswith("https://") for o in ALLOWED_ORIGINS
        ):
            raise RuntimeError("HTTPS et cookies Secure obligatoires")
        if (
            os.getenv("MAIL_MODE") == "local"
            or not os.getenv("SMTP_HOST")
            or not os.getenv("SMTP_FROM")
        ):
            raise RuntimeError("SMTP réel obligatoire hors environnement de test")
    db.pharmacies.create_index("userId", unique=True)
    db.files.create_index("userId", unique=True)
    db.sessions.create_index("expiresAt", expireAfterSeconds=0)
    db.tokens.create_index("expiresAt", expireAfterSeconds=0)
    db.rate_limits.create_index("expiresAt", expireAfterSeconds=0)
    db.notifications.create_index([("recipientId", 1), ("createdAt", -1)])
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.applications.create_index(
        [("candidateId", ASCENDING), ("jobId", ASCENDING)], unique=True
    )
    db.joboffers.create_index([("recruiterId", ASCENDING), ("status", ASCENDING)])
    db.candidates.create_index([("userId", ASCENDING)])
    db.messages.create_index([("applicationId", ASCENDING), ("createdAt", ASCENDING)])
    db.saved_jobs.create_index(
        [("candidateId", ASCENDING), ("jobId", ASCENDING)], unique=True
    )


def write_cookie(response: Response, token: str, csrf: str):
    response.set_cookie(
        COOKIE,
        token,
        max_age=604800,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite=os.getenv("COOKIE_SAMESITE", "lax"),
        path="/",
    )
    # Le CSRF est renvoyé explicitement et reste en mémoire côté front.
    return csrf


@app.post("/api/auth/signup", status_code=201)
def signup(data: Signup, response: Response, request: Request):
    throttle(request, "signup", 10)
    email = normalized_email(data.email)
    if db.users.find_one({"email": email}):
        raise HTTPException(409, "Adresse email déjà utilisée")
    document = {
        "email": email,
        "passwordHash": v2_hash(data.password),
        "role": data.role,
        "name": data.name.strip(),
        "phone": data.phone,
        "createdAt": utcnow(),
    }
    try:
        document["_id"] = db.users.insert_one(document).inserted_id
    except DuplicateKeyError:
        raise HTTPException(409, "Adresse email déjà utilisée")
    issue_email_token(document, "verify")
    token, csrf = signed_session(document)
    write_cookie(response, token, csrf)
    return {"user": public_user(document), "csrfToken": csrf}


@app.post("/api/auth/login")
def login(data: Login, response: Response, request: Request):
    throttle(request, "login", 20)
    user = db.users.find_one({"email": normalized_email(data.email)})
    if (
        not user
        or not verify_password(data.password, user.get("passwordHash", ""))
        or user["role"] != data.role
        or user.get("disabled")
    ):
        raise HTTPException(401, "Identifiants incorrects")
    if user["role"] == "ADMIN":
        import pyotp

        if not user.get("totpSecret") or not pyotp.TOTP(user["totpSecret"]).verify(
            data.otp, valid_window=0
        ):
            raise HTTPException(401, "Code de sécurité incorrect")
        step = int(utcnow().timestamp()) // 30
        if not db.users.update_one(
            {"_id": user["_id"], "lastTotpStep": {"$ne": step}},
            {"$set": {"lastTotpStep": step}},
        ).modified_count:
            raise HTTPException(401, "Code déjà utilisé")
    token, csrf = signed_session(user)
    write_cookie(response, token, csrf)
    return {"user": public_user(user), "csrfToken": csrf}


@app.get("/api/auth/me")
def me(request: Request, user=Depends(current_user)):
    return {"user": public_user(user), "csrfToken": session_payload(request)["csrf"]}


@app.post("/api/auth/logout")
def logout(response: Response, request: Request, user=Depends(current_user)):
    db.sessions.delete_one({"sid": session_payload(request)["sid"]})
    response.delete_cookie(
        COOKIE,
        path="/",
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite=os.getenv("COOKIE_SAMESITE", "lax"),
    )
    return {"ok": True}


@app.get("/api/joboffers")
def get_jobs():
    return [
        serialize(x)
        for x in db.joboffers.find(
            {"sector": "OFFICINE", "status": "OPEN", "title": {"$in": TITLES}}
        )
        .sort("createdAt", -1)
        .limit(200)
    ]


@app.get("/api/joboffers/{job_id}")
def get_job(job_id: str):
    job = db.joboffers.find_one({"_id": identifier(job_id), "sector": "OFFICINE"})
    if not job:
        raise HTTPException(404, "Offre introuvable")
    return serialize(job)


@app.post("/api/joboffers", status_code=201)
def create_job(data: JobInput, user=Depends(role_required("RECRUITER"))):
    require_verified(user)
    if not db.pharmacies.find_one({"userId": user["_id"], "approved": True}):
        raise HTTPException(
            403, "Votre officine doit être validée par un administrateur"
        )
    now = utcnow()
    doc = data.model_dump()
    doc.update(
        {
            "recruiterId": user["_id"],
            "postedDate": now,
            "createdAt": now,
            "updatedAt": now,
            "experience": doc["experienceLevel"],
            "applicants": 0,
            "rating": 0,
            "status": "OPEN",
        }
    )
    doc["_id"] = db.joboffers.insert_one(doc).inserted_id
    return serialize(doc)


@app.get("/api/my/jobs")
def own_jobs(user=Depends(role_required("RECRUITER"))):
    return [
        serialize(x)
        for x in db.joboffers.find({"recruiterId": user["_id"]}).sort("createdAt", -1)
    ]


class JobStatusInput(StrictModel):
    status: Literal["OPEN", "CLOSED"]


@app.patch("/api/my/jobs/{job_id}/status")
def close_job(
    job_id: str, data: JobStatusInput, user=Depends(role_required("RECRUITER"))
):
    query = {"_id": identifier(job_id), "recruiterId": user["_id"]}
    if not db.joboffers.find_one(query):
        raise HTTPException(404, "Offre introuvable")
    if data.status == "OPEN":
        require_verified(user)
        if not db.pharmacies.find_one({"userId": user["_id"], "approved": True}):
            raise HTTPException(403, "Officine non validée")
    updated = db.joboffers.find_one_and_update(
        query,
        {"$set": {"status": data.status, "updatedAt": utcnow()}},
        return_document=True,
    )
    return serialize(updated)


@app.get("/api/candidates")
def candidates(user=Depends(role_required("RECRUITER"))):
    require_verified(user)
    if not db.pharmacies.find_one({"userId": user["_id"], "approved": True}):
        raise HTTPException(403, "Officine non validée")
    profiles = db.candidates.find({"visible": True, "title": {"$in": TITLES}}).limit(
        100
    )
    return [serialize(p) for p in profiles]


@app.get("/api/candidates/{candidate_id}")
def candidate_detail(candidate_id: str, user=Depends(current_user)):
    if user["role"] == "RECRUITER":
        require_verified(user)
        if not db.pharmacies.find_one({"userId": user["_id"], "approved": True}):
            raise HTTPException(403, "Officine non validée")
    target = identifier(candidate_id)
    if user["role"] == "CANDIDATE" and user["_id"] != target:
        raise HTTPException(403, "Accès interdit")
    query = (
        {"userId": target}
        if user["role"] == "CANDIDATE"
        else {"$or": [{"userId": target}, {"_id": target}]}
    )
    profile = db.candidates.find_one(query)
    related = db.applications.find_one(
        {"candidateId": target, "recruiterId": user["_id"]}
    )
    if not profile or (
        user["role"] == "RECRUITER" and not profile.get("visible") and not related
    ):
        raise HTTPException(404, "Profil introuvable")
    owner = db.users.find_one({"_id": profile.get("userId")})
    if not owner or owner.get("disabled"):
        raise HTTPException(404, "Profil introuvable")
    return serialize(profile)


@app.put("/api/candidates/{candidate_id}")
def update_candidate(
    candidate_id: str, data: ProfileInput, user=Depends(role_required("CANDIDATE"))
):
    if identifier(candidate_id) != user["_id"]:
        raise HTTPException(403, "Modification d'un autre profil interdite")
    values = data.model_dump(exclude_unset=True)
    if values.get("title") and values["title"] not in TITLES:
        raise HTTPException(422, "Métier hors officine")
    if (
        "professionalExperiences" in values
        and values["professionalExperiences"] is not None
        and len(values["professionalExperiences"]) > 20
    ):
        raise HTTPException(422, "Trop d'expériences")
    if (
        "skills" in values
        and values["skills"] is not None
        and len(values["skills"]) > 40
    ):
        raise HTTPException(422, "Trop de compétences")
    identity = {k: values[k] for k in ("name", "phone") if values.get(k)}
    if identity:
        db.users.update_one({"_id": user["_id"]}, {"$set": identity})
    values["updatedAt"] = utcnow()
    db.candidates.update_one(
        {"userId": user["_id"]},
        {"$set": values, "$setOnInsert": {"createdAt": utcnow()}},
        upsert=True,
    )
    return serialize(db.candidates.find_one({"userId": user["_id"]}))


@app.post("/api/jobs/{job_id}/apply", status_code=201)
def apply(
    job_id: str, data: ApplicationInput, user=Depends(role_required("CANDIDATE"))
):
    require_verified(user)
    if not db.candidates.find_one({"userId": user["_id"], "title": {"$in": TITLES}}):
        raise HTTPException(422, "Complétez votre profil officinal avant de postuler")
    job = db.joboffers.find_one(
        {"_id": identifier(job_id), "sector": "OFFICINE", "status": "OPEN"}
    )
    if not job:
        raise HTTPException(404, "Offre indisponible")
    doc = {
        "jobId": job["_id"],
        "candidateId": user["_id"],
        "recruiterId": job["recruiterId"],
        "message": data.message,
        "status": "ENVOYEE",
        "createdAt": utcnow(),
        "updatedAt": utcnow(),
    }
    try:
        doc["_id"] = db.applications.insert_one(doc).inserted_id
    except DuplicateKeyError:
        raise HTTPException(409, "Vous avez déjà postulé à cette offre")
    db.joboffers.update_one({"_id": job["_id"]}, {"$inc": {"applicants": 1}})
    notify(job["recruiterId"], "Nouvelle candidature", "Une candidature a été reçue.")
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
def application_status(
    application_id: str, data: StatusInput, user=Depends(role_required("RECRUITER"))
):
    from pymongo import ReturnDocument

    item = db.applications.find_one_and_update(
        {"_id": identifier(application_id), "recruiterId": user["_id"]},
        {"$set": {"status": data.status, "updatedAt": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    if not item:
        raise HTTPException(404, "Candidature introuvable")
    notify(item["candidateId"], "Candidature mise à jour", data.status)
    return serialize(item)


def access_application(application_id: str, user):
    a = db.applications.find_one({"_id": identifier(application_id)})
    if not a or user["_id"] not in (a["candidateId"], a["recruiterId"]):
        raise HTTPException(404, "Candidature introuvable")
    return a


@app.get("/api/applications/{application_id}/messages")
def messages(application_id: str, user=Depends(current_user)):
    a = access_application(application_id, user)
    return [
        serialize(x)
        for x in db.messages.find({"applicationId": a["_id"]})
        .sort("createdAt", 1)
        .limit(500)
    ]


@app.post("/api/applications/{application_id}/messages", status_code=201)
def send_message(application_id: str, data: MessageInput, user=Depends(current_user)):
    a = access_application(application_id, user)
    doc = {
        "applicationId": a["_id"],
        "senderId": str(user["_id"]),
        "body": data.body.strip(),
        "createdAt": utcnow(),
    }
    if not doc["body"]:
        raise HTTPException(422, "Message vide")
    doc["_id"] = db.messages.insert_one(doc).inserted_id
    recipient = (
        a["recruiterId"] if user["_id"] == a["candidateId"] else a["candidateId"]
    )
    notify(recipient, "Nouveau message", "Un message vous attend dans votre espace.")
    return serialize(doc)


@app.get("/api/my/saved")
def saved_jobs(user=Depends(role_required("CANDIDATE"))):
    ids = [x["jobId"] for x in db.saved_jobs.find({"candidateId": user["_id"]})]
    return [
        serialize(x)
        for x in db.joboffers.find({"_id": {"$in": ids}, "sector": "OFFICINE"})
    ]


@app.post("/api/jobs/{job_id}/save")
def save_job(job_id: str, user=Depends(role_required("CANDIDATE"))):
    oid = identifier(job_id)
    if not db.joboffers.find_one({"_id": oid, "sector": "OFFICINE"}):
        raise HTTPException(404, "Offre introuvable")
    db.saved_jobs.update_one(
        {"candidateId": user["_id"], "jobId": oid},
        {"$setOnInsert": {"createdAt": utcnow()}},
        upsert=True,
    )
    return {"ok": True}


@app.delete("/api/jobs/{job_id}/save")
def unsave_job(job_id: str, user=Depends(role_required("CANDIDATE"))):
    db.saved_jobs.delete_one({"candidateId": user["_id"], "jobId": identifier(job_id)})
    return {"ok": True}


@app.get("/health")
def health():
    db.command("ping")
    return {"status": "ok"}


# Les limites sont partagées entre les processus via MongoDB (aucune adresse IP en clair).
def throttle(request, action, limit):
    fingerprint = hashlib.sha256(
        (request.client.host if request.client else "unknown").encode()
    ).hexdigest()
    bucket = int(utcnow().timestamp()) // 900
    key = f"{action}:{fingerprint}:{bucket}"
    item = db.rate_limits.find_one_and_update(
        {"_id": key},
        {
            "$inc": {"count": 1},
            "$setOnInsert": {"expiresAt": utcnow() + timedelta(minutes=30)},
        },
        upsert=True,
        return_document=True,
    )
    if item["count"] > limit:
        raise HTTPException(
            429,
            "Trop de tentatives. Réessayez dans 15 minutes.",
            headers={"Retry-After": "900"},
        )


def require_verified(user):
    if not user.get("emailVerified"):
        raise HTTPException(
            403, "Vérifiez votre adresse email dans les paramètres du compte"
        )


def notify(recipient, title, body):
    db.notifications.insert_one(
        {
            "recipientId": recipient,
            "title": title,
            "body": body,
            "read": False,
            "createdAt": utcnow(),
        }
    )


def issue_email_token(user, purpose):
    import smtplib
    from email.message import EmailMessage
    from urllib.parse import urlencode

    raw = secrets.token_urlsafe(40)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    url = (
        os.getenv("PUBLIC_FRONTEND_URL", "http://localhost:8080").rstrip("/")
        + "/account-action?"
        + urlencode({"purpose": purpose, "token": raw})
    )
    record = {
        "digest": digest,
        "userId": user["_id"],
        "purpose": purpose,
        "expiresAt": utcnow() + timedelta(minutes=30),
    }
    # La boîte locale est exclusivement autorisée dans les bases de test.
    if os.getenv("MAIL_MODE") == "local" and ENVIRONMENT in ("test", "development"):
        db.mail_outbox.insert_one(
            {"to": user["email"], "url": url, "createdAt": utcnow()}
        )
    else:
        host = os.getenv("SMTP_HOST")
        if not host:
            raise HTTPException(503, "Le service email n'est pas configuré")
        message = EmailMessage()
        message["From"] = os.environ["SMTP_FROM"]
        message["To"] = user["email"]
        message["Subject"] = "Officine Talents — " + (
            "Vérification de votre adresse"
            if purpose == "verify"
            else "Réinitialisation du mot de passe"
        )
        message.set_content("Ce lien personnel expire dans 30 minutes :\n" + url)
        try:
            with smtplib.SMTP(
                host, int(os.getenv("SMTP_PORT", "587")), timeout=10
            ) as smtp:
                smtp.starttls()
                if os.getenv("SMTP_USER"):
                    smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException):
            raise HTTPException(503, "Envoi email indisponible, veuillez réessayer")
    db.tokens.insert_one(record)


class EmailInput(StrictModel):
    email: str = Field(max_length=254)


class TokenInput(StrictModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(default="", max_length=128)


def consume_token(raw, purpose):
    token = db.tokens.find_one_and_delete(
        {
            "digest": hashlib.sha256(raw.encode()).hexdigest(),
            "purpose": purpose,
            "expiresAt": {"$gt": utcnow()},
        }
    )
    if not token:
        raise HTTPException(400, "Lien expiré ou déjà utilisé")
    return token


@app.post("/api/auth/forgot-password")
def forgot_password(data: EmailInput, request: Request):
    throttle(request, "forgot", 5)
    user = db.users.find_one(
        {"email": normalized_email(data.email), "disabled": {"$ne": True}}
    )
    if user:
        issue_email_token(user, "reset")
    return {"message": "Si ce compte existe, un lien vous sera envoyé."}


@app.post("/api/auth/reset-password")
def reset_password(data: TokenInput, request: Request):
    throttle(request, "reset", 10)
    if len(data.password) < 10:
        raise HTTPException(422, "10 caractères minimum")
    token = consume_token(data.token, "reset")
    db.users.update_one(
        {"_id": token["userId"]},
        {
            "$set": {"passwordHash": v2_hash(data.password)},
            "$inc": {"sessionVersion": 1},
        },
    )
    db.sessions.delete_many({"userId": token["userId"]})
    return {"ok": True}


@app.post("/api/auth/verify-email")
def verify_email(data: TokenInput, request: Request):
    throttle(request, "verify", 20)
    token = consume_token(data.token, "verify")
    db.users.update_one({"_id": token["userId"]}, {"$set": {"emailVerified": True}})
    return {"ok": True}


@app.post("/api/auth/resend-verification")
def resend_verification(request: Request, user=Depends(current_user)):
    throttle(request, "resend", 3)
    if not user.get("emailVerified"):
        issue_email_token(user, "verify")
    return {"ok": True}


class PasswordInput(StrictModel):
    currentPassword: str = Field(min_length=1, max_length=128)
    newPassword: str = Field(min_length=10, max_length=128)


@app.put("/api/account/password")
def change_password(data: PasswordInput, user=Depends(current_user)):
    if not verify_password(data.currentPassword, user.get("passwordHash", "")):
        raise HTTPException(403, "Mot de passe actuel incorrect")
    db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"passwordHash": v2_hash(data.newPassword)},
            "$inc": {"sessionVersion": 1},
        },
    )
    db.sessions.delete_many({"userId": user["_id"]})
    return {"ok": True}


class DeleteInput(StrictModel):
    password: str = Field(min_length=1, max_length=128)


@app.post("/api/account/deletion-request")
def delete_account(data: DeleteInput, user=Depends(current_user)):
    if not verify_password(data.password, user.get("passwordHash", "")):
        raise HTTPException(403, "Mot de passe incorrect")
    db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"disabled": True, "deletionRequestedAt": utcnow()},
            "$inc": {"sessionVersion": 1},
        },
    )
    db.candidates.update_many({"userId": user["_id"]}, {"$set": {"visible": False}})
    db.joboffers.update_many(
        {"recruiterId": user["_id"]}, {"$set": {"status": "CLOSED"}}
    )
    db.sessions.delete_many({"userId": user["_id"]})
    return {
        "message": "Compte désactivé. La demande d'effacement sera traitée par l'administrateur selon les obligations de conservation."
    }


class PharmacyInput(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    location: str = Field(min_length=2, max_length=100)
    commune: str = Field(min_length=2, max_length=100)
    address: str = Field(min_length=5, max_length=300)
    phone: str = Field(min_length=8, max_length=30)
    registrationNumber: str = Field(min_length=3, max_length=100)
    about: str = Field(default="", max_length=4000)
    country: Literal["DZ"] = "DZ"
    sector: Literal["OFFICINE"] = "OFFICINE"


@app.get("/api/my/profile")
def own_profile(user=Depends(current_user)):
    collection = db.pharmacies if user["role"] == "RECRUITER" else db.candidates
    item = collection.find_one({"userId": user["_id"]})
    return serialize(item) if item else {"name": user.get("name", "")}


@app.put("/api/my/pharmacy")
def save_pharmacy(data: PharmacyInput, user=Depends(role_required("RECRUITER"))):
    db.pharmacies.update_one(
        {"userId": user["_id"]},
        {"$set": {**data.model_dump(), "approved": False, "updatedAt": utcnow()}},
        upsert=True,
    )
    db.joboffers.update_many(
        {"recruiterId": user["_id"]},
        {"$set": {"status": "CLOSED", "updatedAt": utcnow()}},
    )
    return serialize(db.pharmacies.find_one({"userId": user["_id"]}))


@app.put("/api/my/jobs/{job_id}")
def edit_job(job_id: str, data: JobInput, user=Depends(role_required("RECRUITER"))):
    require_verified(user)
    pharmacy = db.pharmacies.find_one({"userId": user["_id"], "approved": True})
    if not pharmacy:
        raise HTTPException(403, "Officine non validée")
    result = db.joboffers.update_one(
        {"_id": identifier(job_id), "recruiterId": user["_id"]},
        {"$set": {**data.model_dump(), "updatedAt": utcnow()}},
    )
    if not result.matched_count:
        raise HTTPException(404, "Offre introuvable")
    return {"ok": True}


@app.get("/api/my/notifications")
def notifications(user=Depends(current_user)):
    return [
        serialize(n)
        for n in db.notifications.find({"recipientId": user["_id"]})
        .sort("createdAt", -1)
        .limit(100)
    ]


@app.patch("/api/my/notifications/read")
def mark_notifications_read(user=Depends(current_user)):
    db.notifications.update_many({"recipientId": user["_id"]}, {"$set": {"read": True}})
    return {"ok": True}


@app.post("/api/my/cv")
def upload_cv(file: UploadFile = File(...), user=Depends(role_required("CANDIDATE"))):
    from io import BytesIO
    from pypdf import PdfReader

    content = file.file.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(413, "CV limité à 2 Mo")
    if file.content_type != "application/pdf" or not content.startswith(b"%PDF-"):
        raise HTTPException(422, "Un fichier PDF valide est requis")
    try:
        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted or len(reader.pages) > 10:
            raise ValueError("PDF non accepté")
        if ENVIRONMENT in ("staging", "production"):
            scan_pdf(content)
        forbidden = {
            "/JavaScript",
            "/JS",
            "/Launch",
            "/OpenAction",
            "/AA",
            "/EmbeddedFiles",
            "/RichMedia",
            "/XFA",
            "/SubmitForm",
            "/ImportData",
        }
        for obj in reader.resolved_objects.values():
            if isinstance(obj, dict) and forbidden.intersection(obj):
                raise ValueError("Contenu actif interdit")
        for page in reader.pages:
            for annotation in page.get("/Annots", []):
                obj = annotation.get_object()
                if "/A" in obj or "/AA" in obj:
                    raise ValueError("Actions interdites")
        root = reader.trailer["/Root"]
        if any(key in root for key in ("/OpenAction", "/AA", "/Names")):
            raise ValueError("Contenu actif interdit")
    except Exception:
        raise HTTPException(
            422, "PDF invalide, chiffré ou contenant des éléments actifs"
        )
    db.files.update_one(
        {"userId": user["_id"]},
        {"$set": {"content": content, "updatedAt": utcnow()}},
        upsert=True,
    )
    db.candidates.update_one(
        {"userId": user["_id"]}, {"$set": {"hasCV": True}}, upsert=True
    )
    return {"ok": True}


@app.get("/api/candidates/{candidate_id}/cv")
def download_cv(candidate_id: str, user=Depends(current_user)):
    target = identifier(candidate_id)
    if target != user["_id"]:
        candidate_detail(candidate_id, user)
    doc = db.files.find_one({"userId": target})
    if not doc:
        raise HTTPException(404, "CV indisponible")
    return Response(
        bytes(doc["content"]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=cv.pdf",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/admin/overview")
def admin_overview(user=Depends(role_required("ADMIN"))):
    return {
        "users": [
            public_user(u)
            | {
                "disabled": bool(u.get("disabled")),
                "deletionRequested": bool(u.get("deletionRequestedAt")),
            }
            for u in db.users.find().limit(200)
        ],
        "pharmacies": [serialize(x) for x in db.pharmacies.find().limit(200)],
        "jobs": [serialize(x) for x in db.joboffers.find().limit(200)],
    }


class ModerationInput(StrictModel):
    approved: bool


@app.patch("/api/admin/pharmacies/{user_id}")
def approve_pharmacy(
    user_id: str, data: ModerationInput, user=Depends(role_required("ADMIN"))
):
    target = identifier(user_id)
    result = db.pharmacies.update_one(
        {"userId": target}, {"$set": {"approved": data.approved}}
    )
    if not result.matched_count:
        raise HTTPException(404, "Officine introuvable")
    db.audit.insert_one(
        {
            "actor": str(user["_id"]),
            "action": "pharmacy.approval",
            "target": user_id,
            "approved": data.approved,
            "createdAt": utcnow(),
        }
    )
    if not data.approved:
        db.joboffers.update_many(
            {"recruiterId": target}, {"$set": {"status": "CLOSED"}}
        )
    notify(
        target,
        "Validation de l'officine",
        "Officine validée" if data.approved else "Validation retirée",
    )
    return {"ok": True}


class DisabledInput(StrictModel):
    disabled: bool


@app.patch("/api/admin/users/{user_id}")
def suspend_user(
    user_id: str, data: DisabledInput, user=Depends(role_required("ADMIN"))
):
    target = identifier(user_id)
    other = db.users.find_one({"_id": target})
    if (
        not other
        or other["role"] == "ADMIN"
        or (other.get("deletionRequestedAt") and not data.disabled)
    ):
        raise HTTPException(403, "Action interdite")
    db.users.update_one(
        {"_id": target},
        {"$set": {"disabled": data.disabled}, "$inc": {"sessionVersion": 1}},
    )
    db.sessions.delete_many({"userId": target})
    if data.disabled:
        db.candidates.update_many({"userId": target}, {"$set": {"visible": False}})
        db.joboffers.update_many(
            {"recruiterId": target}, {"$set": {"status": "CLOSED"}}
        )
    db.audit.insert_one(
        {
            "actor": str(user["_id"]),
            "action": "user.suspension",
            "target": user_id,
            "disabled": data.disabled,
            "createdAt": utcnow(),
        }
    )
    return {"ok": True}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if (
        request.method not in ("GET", "HEAD", "OPTIONS")
        and request.headers.get("origin", "").rstrip("/") not in ALLOWED_ORIGINS
    ):
        return Response(
            content='{"detail":"Origine non autorisée"}',
            status_code=403,
            media_type="application/json",
        )
    if (
        request.headers.get("content-length", "0").isdigit()
        and int(request.headers.get("content-length", "0")) > 3 * 1024 * 1024
    ):
        return Response(status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


def scan_pdf(content):
    """ClamAV INSTREAM : indisponibilité ou détection entraîne un refus fermé."""
    import socket
    import struct

    host = os.getenv("CLAMAV_HOST")
    if not host:
        raise ValueError("Antivirus indisponible")
    with socket.create_connection(
        (host, int(os.getenv("CLAMAV_PORT", "3310"))), timeout=10
    ) as conn:
        conn.sendall(b"zINSTREAM\0")
        for start in range(0, len(content), 65536):
            block = content[start : start + 65536]
            conn.sendall(struct.pack("!I", len(block)) + block)
        conn.sendall(struct.pack("!I", 0))
        result = conn.recv(4096)
        if not result.rstrip(b"\0\n").endswith(b": OK"):
            raise ValueError("Analyse antivirus refusée")


@app.patch("/api/admin/jobs/{job_id}/close")
def admin_close_job(job_id: str, user=Depends(role_required("ADMIN"))):
    result = db.joboffers.update_one(
        {"_id": identifier(job_id)},
        {"$set": {"status": "CLOSED", "updatedAt": utcnow()}},
    )
    if not result.matched_count:
        raise HTTPException(404, "Offre introuvable")
    db.audit.insert_one(
        {
            "actor": str(user["_id"]),
            "action": "job.close",
            "target": job_id,
            "createdAt": utcnow(),
        }
    )
    return {"ok": True}
