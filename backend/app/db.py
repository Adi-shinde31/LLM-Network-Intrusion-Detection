# app/db.py
 
from pymongo import MongoClient
from gridfs import GridFS
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

client = MongoClient(MONGO_URI)

db = client["network_ai"]

uploads_collection = db["uploads"]
files_collection = db["files"]
fs = GridFS(db)