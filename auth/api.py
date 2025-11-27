
from typing import Annotated

from fastapi import APIRouter, Depends

from auth.models import LoginRequest, Token, User
from auth.service import get_auth_user, login

auth_router = APIRouter()

@auth_router.post("/login")
async def login_for_access_token(loginRequest: LoginRequest
) -> Token:
    return login(loginRequest.username, loginRequest.password)


@auth_router.get("/me", response_model=User)
async def users_me(
    current_user: Annotated[User, Depends(get_auth_user)]
):
    return current_user
