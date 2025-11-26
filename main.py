from typing import Annotated, Union

from fastapi import FastAPI, Request
from fastapi.params import Depends
from auth.api import auth_router
from auth.models import User
from auth.service import get_current_active_user

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.get("/health")
def read_root(request: Request):
    print(request.headers)
    return {"Hello": "World", "headers": dict(request.headers)}


@app.get("/me/")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request
):
    return {"user": current_user, "headers": dict(request.headers)}


@app.get("/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]