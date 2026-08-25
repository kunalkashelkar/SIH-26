from fastapi import FastAPI
import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from api.routes import router

app = FastAPI(title="Sentinel Security Scanner API")

app.include_router(router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
