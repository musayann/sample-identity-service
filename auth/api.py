
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.security import OAuth2PasswordRequestForm

from auth.models import LoginRequest, Token, User
from auth.service import get_current_active_user, login

auth_router = APIRouter()

@auth_router.post("/login")
async def login_for_access_token(loginRequest: LoginRequest
) -> Token:
    print("Login attempt for user:", loginRequest.username)
    return login(loginRequest.username, loginRequest.password)

@auth_router.get("/health")
def read_root(request: Request):
    print(request.headers)
    return {"Hello": "World", "headers": dict(request.headers)}
