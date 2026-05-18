from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel, Field
from typing import List, Optional
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
