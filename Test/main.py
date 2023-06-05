from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPBearer
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from pymongo import MongoClient
from jose import jwt, JWTError

app = FastAPI()

client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
users_collection = db["users"]

# JWT configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

# User Model
class User(BaseModel):
    username: str
    password: str

# Token Model
class Token(BaseModel):
    access_token: str
    token_type: str

# JWT Security
security = HTTPBearer()

# Authentication and Token Generation
def authenticate_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user or user["password"] != password:
        return False
    return True

def create_token(username: str):
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expiration}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def get_username_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        return None


@app.post("/registation")
def create_user(user: User):
    existing_user = users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    user_data = jsonable_encoder(user)
    users_collection.insert_one(user_data)
    return {"message": "User created successfully"}


@app.post("/login")
def login(user: User):
    if not authenticate_user(user.username, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(user.username)
    return Token(access_token=token, token_type="bearer")



