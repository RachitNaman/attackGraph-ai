"""
models/responses/auth.py
=========================
Pydantic response models for authentication endpoints.

CRITICAL: AccountResponse deliberately has no `hashed_password` field.
Pydantic response_model filtering means even if a service accidentally
passed the hash through, this model would strip it before serialization.
That's a defense-in-depth reason to always define an explicit response
model rather than returning raw dicts from Neo4j.
"""

from pydantic import BaseModel


class AccountResponse(BaseModel):
    id: str
    email: str
    full_name: str = ""


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    account: AccountResponse
