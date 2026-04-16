# app/schema.py

from typing import Optional
from pydantic import BaseModel

class ParsedTask(BaseModel):
    data_type: str
    data_source: str
    target: Optional[str] = None
    time_window_minutes: Optional[int] = None
    row_limit: Optional[int] = None
    operation_type: str
    analysis_type: Optional[str] = None
    save_output: bool
    file_path: Optional[str] = None
    file_type: Optional[str] = None