# Real-Time Network Traffic Classifier

An LLM-powered network security control plane. You describe what you want analyzed in plain English (e.g. *"detect brute force attacks on the uploaded file"*), and the system parses that into a structured task, runs the right ML model against your network data, and explains the results in plain language with a confidence score and recommendations.

## How it works

1. **Parse** — Your prompt is sent to an LLM (OpenAI function calling) and converted into a structured task: data source, analysis type, row limits, etc.
2. **Load data** — Data comes from either an uploaded CSV/PCAP file (stored in MongoDB via GridFS) or a live packet capture (via `tshark`/`pyshark`) grouped into flows.
3. **Analyze** — An `IsolationForest` model flags anomalous flows for one of four analysis types: general anomaly detection, brute force, MITM, or DoS detection. Results are reduced to 2D with PCA for visualization.
4. **Explain** — The ML output is summarized by an LLM into a human-readable explanation, confidence score, and recommended actions (with a deterministic fallback if the LLM call fails).

## Stack

- **Backend**: FastAPI, scikit-learn, pandas, pyshark, MongoDB (GridFS for file storage)
- **Frontend**: Next.js (App Router), React, Recharts (PCA scatter plot)

## Getting started

### Prerequisites
- Python 3.10+, Node.js, MongoDB running locally (or a connection URI), and [Wireshark/tshark](https://www.wireshark.org/) installed for PCAP/live capture support.
- An OpenAI API key.

### Backend

```bash
cd backend
pip install -r requirements.txt
```

Create `backend/.env`:
```
OPENAI_API_KEY=your-key-here
MONGO_URI=mongodb://localhost:27017
```

Run the API:
```bash
uvicorn app.main:app --reload --app-dir .
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Generating test traffic

For live-capture mode, you need some traffic flowing on your interface. A simple way to generate it:
```bash
ping google.com -t
```

## Project structure

```
backend/
  app/
    main.py         # FastAPI app & upload endpoints
    llm_parser.py   # Prompt -> structured task (OpenAI function calling)
    mcp.py          # Orchestrates the analyze pipeline + LLM explanation
    ml_models.py    # IsolationForest-based anomaly/attack detection + PCA
    data_handler.py # Live capture -> flow aggregation
    file_parsers.py # PCAP/CSV parsing, interface detection
    db.py           # MongoDB / GridFS client
    schema.py        # ParsedTask pydantic model
frontend/
  app/
    page.tsx        # Main dashboard UI
    PCAChart.tsx    # PCA scatter plot (Recharts)
```

## Notes

- `OPENAI_API_KEY` is required at startup — the backend will refuse to boot without it.
- Uploaded files and generated output (`backend/uploads/`, `backend/output/`) are git-ignored; nothing there is meant to be committed.
