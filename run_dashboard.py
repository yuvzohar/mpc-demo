#!/usr/bin/env python3
import uvicorn
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from dashboard.server import app

if __name__ == "__main__":
    print("\n  MCP Security Dashboard")
    print("  Open http://localhost:8000 in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
