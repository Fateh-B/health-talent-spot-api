from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List, Optional
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# CORS - one line, works
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI"))
db = client["health_talent_spot"]

class JobOffer(BaseModel):
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
    postedDate: str = "Récemment"
    applicants: int = 0
    rating: float = 4.5

@app.get("/api/joboffers", response_model=List[JobOffer])
def get_jobs():
    raw_jobs = list(db.joboffers.find({}, {"_id": 0}))
    jobs = []
    for job in raw_jobs:
        job["postedDate"] = str(job.get("postedDate", "Récemment"))
        job["rating"] = float(str(job.get("rating", 4.5)))
        jobs.append(job)
    return jobs

@app.get("/api/db-test")
def db_test():
    doc = db.user.find_one({})
    return {"username": doc["username"]}
