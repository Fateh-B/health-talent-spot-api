from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel, Field
from typing import List, Optional
from bson.errors import InvalidId
from bson.objectid import ObjectId
import os
import hashlib
import secrets
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex=r"https://.*\.netlify\.app|http://localhost:.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI"))
db = client["health_talent_spot"]

class JobOffer(BaseModel):
    id: str
    title: str
    sector: str
    specialty: Optional[str] = None
    location: str
    contractType: str
    salary: int
    salaryPeriod: Optional[str] = None
    experience: str
    genderPreference: str
    description: str
    requiredSkills: str
    recruiterId: str
    postedDate: str
    applicants: int
    rating: float


class JobOfferCreate(BaseModel):
    title: str
    sector: str
    specialty: Optional[str] = None
    location: str
    contractType: str
    salary: int
    salaryPeriod: str
    experienceLevel: str = Field(alias="experienceLevel")
    genderPreference: str
    description: str
    requiredSkills: str


class UserSignup(BaseModel):
    email: str
    password: str
    role: str
    name: Optional[str] = None
    phone: Optional[str] = None


class UserLogin(BaseModel):
    email: str
    password: str
    role: str


class CandidateExperienceInput(BaseModel):
    title: Optional[str] = None
    company: Optional[str] = None
    period: Optional[str] = None
    description: Optional[str] = None


class CandidateProfileUpdate(BaseModel):
    userId: Optional[str] = None
    name: Optional[str] = None
    title: Optional[str] = None
    role: Optional[str] = None
    specialty: Optional[str] = None
    location: Optional[str] = None
    experience: Optional[str] = None
    availability: Optional[str] = None
    about: Optional[str] = None
    skills: Optional[List[str]] = None
    professionalExperiences: Optional[List[CandidateExperienceInput]] = None


def hash_password(password: str):
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
    return f"{salt}:{password_hash}"


def verify_password(password: str, stored_password: str):
    salt, password_hash = stored_password.split(":")
    test_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()
    return secrets.compare_digest(test_hash, password_hash)


def serialize_user(user):
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "role": user["role"],
        "name": user.get("name"),
        "phone": user.get("phone"),
    }


def serialize_candidate(candidate):
    candidate = dict(candidate)
    candidate["id"] = str(candidate.pop("_id"))
    candidate.pop("passwordHash", None)

    account_role = candidate.get("role")
    if account_role in {"CANDIDATE", "RECRUITER"}:
        candidate["accountRole"] = account_role
        candidate.pop("role", None)

    if not candidate.get("name") and candidate.get("email"):
        candidate["name"] = candidate["email"].split("@")[0]

    if isinstance(candidate.get("createdAt"), datetime):
        candidate["createdAt"] = candidate["createdAt"].isoformat()
    if isinstance(candidate.get("updatedAt"), datetime):
        candidate["updatedAt"] = candidate["updatedAt"].isoformat()

    for key in ("userId", "candidateId"):
        if isinstance(candidate.get(key), ObjectId):
            candidate[key] = str(candidate[key])

    return candidate


def get_candidate_filter(candidate_id: str):
    try:
        object_id = ObjectId(candidate_id)
    except InvalidId:
        raise HTTPException(status_code=404, detail="Candidate not found")

    return object_id, {
        "$or": [
            {"_id": object_id},
            {"userId": object_id},
            {"userId": candidate_id},
        ]
    }


def time_ago(date):
    if isinstance(date, str):
        return date
    now = datetime.utcnow()
    diff = now - date
    days = diff.days
    
    if days == 0:
        hours = diff.seconds // 3600
        if hours == 0:
            return "À l'instant"
        return f"Il y a {hours} heure{'s' if hours > 1 else ''}"
    if days == 1:
        return "Hier"
    if days < 31:
        return f"Il y a {days} jours"
    if days < 365:
        months = days // 30
        return f"Il y a {months} mois"
    
    years = days // 365
    return f"Il y a {years} an{'s' if years > 1 else ''}"


@app.post("/api/auth/signup", status_code=201)
def signup(data: UserSignup):
    email = data.email.strip().lower()
    if db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already exists")

    user_doc = {
        "email": email,
        "passwordHash": hash_password(data.password),
        "role": data.role,
        "name": data.name,
        "phone": data.phone,
        "createdAt": datetime.utcnow(),
    }
    result = db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    return {"user": serialize_user(user_doc)}


@app.post("/api/auth/login")
def login(data: UserLogin):
    email = data.email.strip().lower()
    user = db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["passwordHash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user["role"] != data.role:
        raise HTTPException(status_code=403, detail="This account does not match the selected role")

    return {"user": serialize_user(user)}


@app.get("/api/candidates")
def get_candidates():
    candidates = list(db.candidates.find({}))
    profile_user_ids = {
        str(candidate.get("userId"))
        for candidate in candidates
        if candidate.get("userId")
    }

    candidate_users = [
        user
        for user in db.users.find({"role": "CANDIDATE"})
        if str(user["_id"]) not in profile_user_ids
    ]

    return [serialize_candidate(candidate) for candidate in candidates + candidate_users]


@app.get("/api/candidates/{candidate_id}")
def get_candidate(candidate_id: str):
    object_id, candidate_filter = get_candidate_filter(candidate_id)
    candidate = db.candidates.find_one(candidate_filter)
    if not candidate:
        candidate = db.users.find_one({"_id": object_id, "role": "CANDIDATE"})

    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    return serialize_candidate(candidate)


@app.put("/api/candidates/{candidate_id}")
def upsert_candidate(candidate_id: str, profile: CandidateProfileUpdate):
    object_id, candidate_filter = get_candidate_filter(candidate_id)
    now = datetime.utcnow()
    profile_doc = profile.model_dump(exclude_unset=True)

    user_id = profile_doc.get("userId")
    if user_id:
        try:
            profile_doc["userId"] = ObjectId(user_id)
        except InvalidId:
            raise HTTPException(status_code=400, detail="Invalid user id")
    elif db.users.find_one({"_id": object_id, "role": "CANDIDATE"}):
        profile_doc["userId"] = object_id

    profile_doc["updatedAt"] = now

    existing_candidate = db.candidates.find_one(candidate_filter)
    if existing_candidate:
        db.candidates.update_one({"_id": existing_candidate["_id"]}, {"$set": profile_doc})
        candidate = db.candidates.find_one({"_id": existing_candidate["_id"]})
    else:
        profile_doc["createdAt"] = now
        result = db.candidates.insert_one(profile_doc)
        candidate = db.candidates.find_one({"_id": result.inserted_id})

    if profile_doc.get("name") and candidate.get("userId"):
        db.users.update_one({"_id": candidate["userId"]}, {"$set": {"name": profile_doc["name"]}})

    return serialize_candidate(candidate)


@app.get("/api/joboffers", response_model=List[JobOffer])
def get_jobs():
    jobs = list(db.joboffers.find({}))
    for job in jobs:
        job["id"] = str(job.pop("_id"))
        job["postedDate"] = time_ago(job.get("postedDate"))
    return jobs

@app.post("/api/joboffers", status_code=201)
def create_job(job_offer: JobOfferCreate):
    now = datetime.utcnow()
    job_doc = job_offer.model_dump(by_alias=True)
    job_doc.update({
        "experience": job_doc["experienceLevel"],
        "recruiterId": "anonymous",
        "postedDate": now,
        "applicants": 0,
        "rating": 0,
        "createdAt": now,
        "updatedAt": now,
    })

    result = db.joboffers.insert_one(job_doc)
    job_doc["id"] = str(result.inserted_id)
    job_doc.pop("_id", None)
    job_doc["postedDate"] = time_ago(job_doc["postedDate"])
    return job_doc

@app.get("/api/joboffers/{job_id}")
def get_job(job_id: str):
    try:
        object_id = ObjectId(job_id)
    except InvalidId:
        raise HTTPException(status_code=404, detail="Job not found")

    job = db.joboffers.find_one({"_id": object_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job["id"] = str(job.pop("_id"))
    job["postedDate"] = time_ago(job.get("postedDate"))
    return job
