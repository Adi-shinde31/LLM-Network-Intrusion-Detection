"use client";

import { useState } from "react";

export default function Home() {
  const [prompt, setPrompt] = useState("");
  const [parsedTask, setParsedTask] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState("");
  const [error, setError] = useState("");
  const [file, setFile] = useState<File | null>(null);

  /* ================= CLEAR ================= */
  const handleClear = () => {
    setPrompt("");
    setParsedTask(null);
    setResult(null);
    setFile(null);
    setError("");
    setLoading(false);
    setLoadingStep("");
  };

  /* ================= PARSE ================= */
  const handleParse = async () => {
    if (!prompt) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      setLoadingStep("📥 Reading your prompt...");

      const formData = new FormData();
      formData.append("prompt", prompt);

      if (file) {
        setLoadingStep("📂 Uploading file to MongoDB...");
        formData.append("file", file);
      }

      setLoadingStep("🧠 Extracting task structure...");

      const res = await fetch("http://127.0.0.1:8000/parse", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Parse failed");

      const data = await res.json();

      setParsedTask(data);

      // 🔥 IMPORTANT: clear file after upload (Mongo handles it now)
      setFile(null);

      setLoadingStep("✨ Task ready");
    } catch (err) {
      setError("❌ Failed to parse prompt");
    } finally {
      setLoading(false);
      setLoadingStep("");
    }
  };

  /* ================= EXECUTE ================= */
  const handleExecute = async () => {
    if (!parsedTask) return;

    setLoading(true);
    setError("");

    try {
      setLoadingStep("🚀 Initializing analysis engine...");

      const res = await fetch("http://127.0.0.1:8000/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsedTask),
      });

      if (!res.ok) throw new Error("Execution failed");

      setLoadingStep("🤖 Running ML models...");

      const data = await res.json();

      setLoadingStep("📊 Processing results...");
      setResult(data);

      setLoadingStep("🧠 Generating insights...");
    } catch (err) {
      setError("❌ Failed to execute task");
    } finally {
      setLoading(false);
      setLoadingStep("");
    }
  };

  return (
    <div style={styles.container}>
      {/* LOADING */}
      {loading && (
        <div style={styles.overlay}>
          <div style={styles.spinner}></div>
          <h2 style={{ marginTop: "15px" }}>
            {loadingStep || "Processing..."}
          </h2>
          <p style={{ color: "#94a3b8" }}>
            Please wait while we process your request...
          </p>
        </div>
      )}

      {/* HEADER */}
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>🛡️ Cyber Threat Intelligence Platform</h1>
          <p style={styles.subtitle}>
            Real-time anomaly detection & network monitoring
          </p>
        </div>

        <span style={styles.status}>🟢 Active</span>
      </header>

      {/* INPUT */}
      <section style={styles.card}>
        <textarea
          placeholder="Describe your analysis (e.g. detect brute force attacks on uploaded file)"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          style={styles.textarea}
        />

        <div style={styles.row}>
          <label style={styles.uploadBox}>
            📂 Upload CSV / PCAP
            <input
              type="file"
              accept=".csv,.pcap"
              hidden
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
          </label>

          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={handleParse}
              disabled={!prompt || loading}
              style={styles.button}
            >
              🔍 Parse Prompt
            </button>

            <button onClick={handleClear} style={styles.clearButton}>
              🧹 Clear
            </button>
          </div>
        </div>

        {file && <p style={styles.fileName}>✅ {file.name}</p>}
        {error && <p style={styles.error}>{error}</p>}
      </section>

      {/* PARSED TASK */}
      {parsedTask && !result && (
        <section style={styles.card}>
          <h2 style={styles.sectionTitle}>🔍 Confirm Analysis Task</h2>

          {/* 🔥 SHOW DATASET ID */}
          {parsedTask.file_path && (
            <p style={{ color: "#38bdf8", marginBottom: "10px" }}>
              📦 Dataset ID: {parsedTask.file_path}
            </p>
          )}

          {Object.entries(parsedTask).map(([key, value]: any) => (
            <div key={key} style={styles.field}>
              <label style={styles.label}>{key}</label>
              <input
                value={value ?? ""}
                disabled={key === "file_path"} // 🔥 lock Mongo ID
                onChange={(e) =>
                  setParsedTask({
                    ...parsedTask,
                    [key]: e.target.value,
                  })
                }
                style={styles.input}
              />
            </div>
          ))}

          <button onClick={handleExecute} style={styles.button}>
            🚀 Confirm & Run Analysis
          </button>
        </section>
      )}

      {/* RESULTS */}
      {result?.ml_results && (
        <>
          <section style={styles.kpiGrid}>
            <KPI title="Total Records" value={result.ml_results.total_records} />
            <KPI
              title="Suspicious Flows"
              value={result.ml_results.suspicious_flow_count}
              color="#ef4444"
            />
            <KPI
              title="Unique Attackers"
              value={result.ml_results.unique_suspected_attackers}
              color="#f59e0b"
            />
          </section>

          {result.explanation && (
            <section style={styles.card}>
              <h2 style={styles.sectionTitle}>🧠 AI Insight</h2>
              <p>{result.explanation.explanation}</p>

              <div style={styles.confidence}>
                Confidence: {(result.explanation.confidence * 100).toFixed(1)}%
              </div>

              <ul>
                {result.explanation.recommendations?.map(
                  (r: string, i: number) => (
                    <li key={i}>{r}</li>
                  )
                )}
              </ul>
            </section>
          )}
        </>
      )}
    </div>
  );
}

/* KPI */
function KPI({ title, value, color = "#6366f1" }: any) {
  return (
    <div style={{ ...styles.kpiCard, borderTop: `3px solid ${color}` }}>
      <p style={styles.kpiTitle}>{title}</p>
      <h2 style={{ color }}>{value}</h2>
    </div>
  );
}

/* STYLES */
const styles: any = {
  container: {
    padding: "40px",
    background: "linear-gradient(135deg, #0b1220, #0f172a)",
    color: "#f1f5f9",
    minHeight: "100vh",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "30px",
  },
  title: { fontSize: "22px", fontWeight: 700 },
  subtitle: { fontSize: "12px", color: "#94a3b8" },
  status: {
    background: "rgba(34, 197, 94, 0.15)",
    color: "#22c55e",
    padding: "6px 14px",
    borderRadius: "999px",
  },
  card: {
    background: "rgba(30, 41, 59, 0.6)",
    padding: "22px",
    borderRadius: "14px",
    marginBottom: "20px",
  },
  textarea: {
    width: "100%",
    height: "110px",
    padding: "14px",
    borderRadius: "10px",
    background: "#0f172a",
    color: "#fff",
  },
  row: {
    display: "flex",
    justifyContent: "space-between",
    marginTop: "10px",
  },
  button: {
    padding: "10px 16px",
    background: "#6366f1",
    color: "white",
    border: "none",
    borderRadius: "10px",
    cursor: "pointer",
  },
  clearButton: {
    padding: "10px",
    background: "#ef4444",
    color: "white",
    border: "none",
    borderRadius: "10px",
    cursor: "pointer",
  },
  uploadBox: {
    padding: "10px",
    background: "#1e293b",
    borderRadius: "10px",
  },
  fileName: { color: "#22c55e", marginTop: "10px" },
  error: { color: "#ef4444", marginTop: "10px" },
  sectionTitle: { fontSize: "16px", marginBottom: "12px" },
  field: { marginBottom: "10px" },
  label: { fontSize: "12px", color: "#94a3b8" },
  input: {
    width: "100%",
    padding: "10px",
    background: "#0f172a",
    border: "1px solid #334155",
    color: "#fff",
  },
  kpiGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "12px",
    marginBottom: "20px",
  },
  kpiCard: {
    background: "rgba(30, 41, 59, 0.6)",
    padding: "18px",
    borderRadius: "12px",
    textAlign: "center",
  },
  kpiTitle: { fontSize: "12px", color: "#94a3b8" },
  confidence: {
    marginTop: "10px",
    color: "#22c55e",
    fontWeight: 600,
  },
  overlay: {
    position: "fixed",
    inset: 0,
    background: "rgba(0,0,0,0.75)",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    zIndex: 9999,
  },
  spinner: {
    width: "50px",
    height: "50px",
    border: "4px solid #334155",
    borderTop: "4px solid #6366f1",
    borderRadius: "50%",
    animation: "spin 1s linear infinite",
  },
};