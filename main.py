from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel, Field
from typing import List, Optional
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

    return {"user": serialize_user(user)}


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
    from bson.objectid import ObjectId
    job = db.joboffers.find_one({"_id": ObjectId(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job["id"] = str(job.pop("_id"))
    job["postedDate"] = time_ago(job.get("postedDate"))
    return job
