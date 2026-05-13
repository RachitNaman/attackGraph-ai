from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

# Initialize FastAPI app
app = FastAPI(
    title="AttackGraph AI",
    description="Attack path analysis with AI",
    version="0.1.0"
)

# CORS middleware
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AttackGraph AI API"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
