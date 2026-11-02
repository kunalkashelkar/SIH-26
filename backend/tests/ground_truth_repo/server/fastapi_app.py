from fastapi import FastAPI, Depends, Query, Path, Header, HTTPException
from pydantic import BaseModel
import sqlite3
import os

app = FastAPI(title="Controlled Ground Truth API", version="1.0.0")

class UserCreateSchema(BaseModel):
    username: str
    email: str
    password: str

class UserUpdateSchema(BaseModel):
    email: str
    full_name: str

class OrderSchema(BaseModel):
    item_id: int
    quantity: int

def get_current_user(authorization: str = Header(...)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"user": "auth_admin", "role": "admin"}

def require_admin(user: dict = Depends(get_current_user)):
    # Role-based authorization example
    roles_required("admin")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return user

def roles_required(role: str):
    pass

# Hardcoded secret pattern for SAST testing
DEMO_API_KEY = "ghp_mocktoken1234567890abcdef1234567890"

@app.get("/api/v1/users")
def get_all_users(auth: dict = Depends(get_current_user)):
    return []

@app.get("/api/v1/users/{user_id}")
def get_user_by_id(user_id: int = Path(...), verbose: bool = Query(False)):
    # SQL injection candidate pattern for SAST testing
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return {"id": user_id}

@app.post("/api/v1/users")
def create_new_user(user: UserCreateSchema):
    return user

@app.put("/api/v1/users/{user_id}")
def update_user_by_id(user_id: int, user: UserUpdateSchema, auth: dict = Depends(get_current_user)):
    return {"id": user_id, "updated": True}

@app.delete("/api/v1/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_admin)):
    return {"id": user_id, "deleted": True}

@app.post("/api/v1/orders")
def place_order(order: OrderSchema, auth: dict = Depends(get_current_user)):
    return order

@app.get("/api/v1/reports/download")
def download_report(file_path: str = Query(...)):
    # Path traversal candidate sink
    safe_path = os.path.join("/tmp/reports", file_path)
    with open(safe_path, "r") as f:
        return {"content": f.read()}
