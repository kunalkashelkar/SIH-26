# Web Fuzzer Backend

FastAPI backend foundation for the SIH-26 Web Fuzzer.

## Setup

1. Create virtual environment: `python3 -m venv venv`
2. Activate it: `source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Setup `.env` file based on `.env.example`
5. Run server: `uvicorn app.main:app --reload`
