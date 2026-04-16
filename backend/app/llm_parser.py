# app/llm_parser.py

import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from app.schema import ParsedTask

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a control-plane parser for a network security system.

Interpret the user's request and call `create_parsed_task`.

Rules:
- If user says "attached file", "uploaded file", "this file" → data_source = uploaded
- If a website is mentioned, data_source or live = live
- If number of rows is mentioned, set row_limit
- If cleaning is requested without detection, operation_type = clean
- If detection is requested, operation_type = analyze
- If saving is mentioned, save_output = true
- If no saving mentioned, save_output = false
- If no analysis type is specified, set analysis_type = null
- If duration like "5 seconds", "2 minutes" is mentioned → set time_window_minutes

Do not explain anything.
Always call the function.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "create_parsed_task",
            "description": "Create a structured parsed task from user input",
            "parameters": {
                "type": "object",
                "properties": {
                    "data_type": {
                        "type": "string",
                        "enum": ["network_traffic"]
                    },
                    "data_source": {
                        "type": "string",
                        "enum": ["live", "uploaded"]
                    },
                    "target": {
                        "type": ["string", "null"]
                    },
                    "time_window_minutes": {
                        "type": ["number", "null"]
                    },
                    "row_limit": {
                        "type": ["number", "null"]
                    },
                    "operation_type": {
                        "type": "string",
                        "enum": ["analyze", "clean", "fetch_only"]
                    },
                    "analysis_type": {
                        "type": ["string", "null"],
                        "enum": [
                            "anomaly_detection",
                            "brute_force_detection",
                            "mitm_detection",
                            "dos_detection"
                        ]
                    },
                    "save_output": {
                        "type": "boolean"
                    }
                },
                "required": [
                    "data_type",
                    "data_source",
                    "operation_type",
                    "save_output"
                ],
                "additionalProperties": False
            }
        }
    }
]


def parse_user_prompt(user_prompt: str) -> ParsedTask:
    """
    Parses user prompt using OpenAI function calling.
    Returns ParsedTask directly (no terminal confirmation).
    """
    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        tools=TOOLS,
        tool_choice={"type": "function", "function": {"name": "create_parsed_task"}},
        temperature=0
    )

    # Extract function call
    tool_call = response.choices[0].message.tool_calls
    if not tool_call:
        raise RuntimeError("Model did not return a function call")

    arguments = tool_call[0].function.arguments
    parsed_json = json.loads(arguments)

    # Return as ParsedTask object
    return ParsedTask(**parsed_json)