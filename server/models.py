from pydantic import BaseModel
from typing import Dict, Any

class AppSecAction(BaseModel):
    patch_code: str

class AppSecObservation(BaseModel):
    stdout: str
    stderr: str
    file_content: str
    test_results: Dict[str, Any]
