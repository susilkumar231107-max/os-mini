import os
import sys

# Ensure root directory is on the path so app and advisor can be imported
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Signal serverless environment to app.py
os.environ["VERCEL"] = "1"

from app import app
