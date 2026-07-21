"""
api/v1/auth.py
===============
Registration and login routes.

Route handlers have ONE job: validate input (via Pydantic), call the
service, return a response — same convention as graph.py. No password
hashing, no Cypher, no JWT logic here; that all lives in
core/security.py and services/account_service.py.
"""

from fastapi import APIRouter, Depends

from app.models.requests.auth import RegisterRequest, LoginRequest
from app.models.responses.auth import TokenResponse, AccountResponse
from app.services.account_service import account_service
from app.core.security import create_access_token
from app.dependencies import get_current_account

router = APIRouter()


@router.post(
    "/register",
    response_model=TokenResponse,
    summary="Create a new account",
    description="Registers a new account and immediately returns an "
                 "access token, so the client doesn't need a separate "
                 "login call right after registering.",
)
async def register(request: RegisterRequest) -> TokenResponse:
    account = await account_service.register(
        email=request.email,
        password=request.password,
        full_name=request.full_name,
    )
    token = create_access_token(subject=account["id"])
    return TokenResponse(
        access_token=token,
        account=AccountResponse(**account),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in with email and password",
)
async def login(request: LoginRequest) -> TokenResponse:
    account = await account_service.authenticate(
        email=request.email,
        password=request.password,
    )
    token = create_access_token(subject=account["id"])
    return TokenResponse(
        access_token=token,
        account=AccountResponse(**account),
    )


@router.get(
    "/me",
    response_model=AccountResponse,
    summary="Get the currently authenticated account",
)
async def get_me(account: dict = Depends(get_current_account)) -> AccountResponse:
    return AccountResponse(**account)
