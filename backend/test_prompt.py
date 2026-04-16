# test_prompt.py

import json
import os
from app.llm_parser import parse_user_prompt
from app.mcp import execute_task

# 1️⃣ Ask user for prompt
prompt = input("Enter your network analysis prompt: ")

# 2️⃣ Parse user prompt into structured JSON
parsed_task = parse_user_prompt(prompt)

# 3️⃣ Create output folder if it doesn't exist
os.makedirs("output", exist_ok=True)

# 4️⃣ Save structured task
structured_filepath = os.path.join("output", "structured_data.json")
with open(structured_filepath, "w") as f:
    json.dump(parsed_task.model_dump(), f, indent=2)
print(f"✅ Structured task saved to {structured_filepath}")

# 5️⃣ Execute MCP pipeline
mcp_results = execute_task(parsed_task)

# 6️⃣ Save MCP results to JSON
mcp_filepath = os.path.join("output", "mcp_results.json")
with open(mcp_filepath, "w") as f:
    json.dump(mcp_results, f, indent=2)
print(f"✅ MCP execution results saved to {mcp_filepath}")

# 7️⃣ Print summary for user
print("\n===== MCP Execution Summary =====")
print(json.dumps(mcp_results, indent=2))
