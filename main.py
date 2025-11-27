from typing import Annotated

from fastapi import FastAPI, Request
from fastapi.params import Depends
from auth.api import auth_router
from auth.models import User
from auth.service import get_current_user

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.get("/health")
def read_root(request: Request):
    return {"Hello": "World", "headers": dict(request.headers)}


@app.get("/items")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]