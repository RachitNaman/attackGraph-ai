"""
Account Service
===============
The service layer for authentication: registering and authenticating
Accounts (application logins), as opposed to GraphService which
manages the modeled attack-surface data (Hosts, Vulnerabilities, etc.).

RESPONSIBILITIES:
- Hash/verify passwords (delegates to core.security)
- Create Account nodes, enforcing email uniqueness
- Look up accounts by email/id for login and token verification

NOT RESPONSIBILITIES:
- Issuing JWTs (that's core.security.create_access_token, called from
  the route layer once this service confirms credentials are valid)
- HTTP concerns (status codes, request parsing)
"""

import logging
import uuid
from typing import Any

from app.graph.neo4j_client import neo4j_client
from app.graph.queries import accounts as account_queries
from app.core.security import hash_password, verify_password
from app.core.exceptions import AccountExistsError, GraphQueryError
from app.core.security import AuthError

logger = logging.getLogger(__name__)


class AccountService:
    async def register(
        self,
        email: str,
        password: str,
        full_name: str = "",
    ) -> dict[str, Any]:
        """
        Create a new Account. Raises AccountExistsError if the email
        is already taken (enforced at the DB level by a uniqueness
        constraint; we catch the resulting driver error here).
        """
        existing = await neo4j_client.execute_read(
            account_queries.GET_ACCOUNT_BY_EMAIL, {"email": email}
        )
        if existing:
            raise AccountExistsError(f"An account with email {email} already exists")

        account_id = str(uuid.uuid4())

        try:
            results = await neo4j_client.execute_write(
                account_queries.CREATE_ACCOUNT,
                {
                    "id": account_id,
                    "email": email,
                    "hashed_password": hash_password(password),
                    "full_name": full_name,
                },
            )
        except Exception as e:
            # Covers the race where two requests pass the read-check
            # above simultaneously and both try to create the same
            # email — the DB constraint catches it even if our
            # pre-check didn't.
            logger.error(f"Account creation failed for {email}: {e}")
            raise AccountExistsError(f"An account with email {email} already exists")

        if not results:
            raise GraphQueryError("Failed to create account")

        return dict(results[0]["a"])

    async def authenticate(self, email: str, password: str) -> dict[str, Any]:
        """
        Verify email/password. Raises AuthError on any mismatch.

        Deliberately returns the SAME error for "no such account" and
        "wrong password" — distinguishing them lets an attacker enumerate
        which emails are registered.
        """
        results = await neo4j_client.execute_read(
            account_queries.GET_ACCOUNT_BY_EMAIL, {"email": email}
        )
        if not results:
            raise AuthError("Incorrect email or password")

        account = dict(results[0]["a"])
        if not verify_password(password, account["hashed_password"]):
            raise AuthError("Incorrect email or password")

        return account

    async def get_by_id(self, account_id: str) -> dict[str, Any]:
        """Look up an account by id. Raises AuthError if it no longer exists
        (e.g. token is valid but the account was deleted)."""
        results = await neo4j_client.execute_read(
            account_queries.GET_ACCOUNT_BY_ID, {"id": account_id}
        )
        if not results:
            raise AuthError("Account no longer exists")
        return dict(results[0]["a"])


# Singleton instance, matching the pattern used by other services
account_service = AccountService()
