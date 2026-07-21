"""
models/requests/auth.py
========================
Pydantic request models for authentication endpoints.

Validation happens here, at the boundary, before any service or
database code runs — route handlers and services can assume these
fields are already well-formed.
"""

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plaintext password, min 8 characters. Hashed before storage.",
    )
    full_name: str = Field(default="", max_length=100)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)
