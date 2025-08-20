
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app import models, database
from app.routes import router
import os
from dotenv import load_dotenv

load_dotenv()
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Bearister AI")

# CORS settings
app.add_middleware(
	CORSMiddleware,
	allow_origins=["http://localhost:3000"],
	allow_credentials=True,
	allow_methods=["*"] ,
	allow_headers=["*"]
)

app.include_router(router, prefix="/auth", tags=["Auth"])
