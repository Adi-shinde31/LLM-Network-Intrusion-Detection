# app/main.py

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.llm_parser import parse_user_prompt
from app.schema import ParsedTask
from app.mcp import execute_task

import datetime
from app.db import fs

app = FastAPI(title="LLM Network Control Plane")

# ==========================================================
# CORS
# ==========================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# 🔥 STORE CSV IN MONGODB
# ==========================================================
def store_csv_to_mongo(file, filename):

    file.file.seek(0)
    content = file.file.read()

    if not content:
        raise ValueError("Uploaded file is empty")

    file_id = fs.put(
        content,
        filename=filename,
        file_type="csv",
        created_at=datetime.datetime.utcnow()
    )

    return str(file_id)

# ==========================================================
# 🔥 STORE PCAP IN MONGODB
# ==========================================================
def store_pcap_to_mongo(file, filename):

    file.file.seek(0)
    content = file.file.read()

    if not content:
        raise ValueError("Uploaded file is empty")

    file_id = fs.put(
        content,
        filename=filename,
        file_type="pcap",
        created_at=datetime.datetime.utcnow()
    )

    return str(file_id)


# ==========================================================
# 1️⃣ PARSE
# ==========================================================
@app.post("/parse", response_model=ParsedTask)
async def parse_prompt(
    prompt: str = Form(...),
    file: UploadFile = File(None)
):
    file_id = None
    file_type = None

    if file:
        if file.filename.endswith(".csv"):
            file_id = store_csv_to_mongo(file, file.filename)
            file_type = "csv"

        elif file.filename.endswith(".pcap"):
            file_id = store_pcap_to_mongo(file, file.filename)
            file_type = "pcap"

        else:
            raise HTTPException(status_code=400, detail="Only CSV or PCAP files are allowed")

    task = parse_user_prompt(prompt)

    if file_id:
        task.file_path = file_id   # MongoDB ID
        task.file_type = file_type

    return task


# ==========================================================
# 2️⃣ EXECUTE
# ==========================================================
@app.post("/execute")
def run_task(task: ParsedTask):
    return execute_task(task)