"""
Account Queries
================
Cypher queries for the auth `Account` node.

NAMING NOTE:
This project already has a `User` label representing an OS/service
account *inside* the modeled attack graph (e.g. "admin user on the
database host" — domain data an attacker might compromise).

`Account` is a different concept: the application login that owns
data. Reusing `User` for both would collide two unrelated meanings
under one label, which would make every future Cypher query ambiguous
about which "user" it means. Keeping them separate labels avoids that.

CREATE (not MERGE) is used here deliberately, unlike asset queries:
account creation must fail loudly on duplicate emails rather than
silently overwriting an existing account. The uniqueness constraint
on Account.email enforces this at the database level; the service
layer catches the resulting error and raises AccountExistsError.
"""

CREATE_ACCOUNT = """
CREATE (a:Account {
    id: $id,
    email: $email,
    hashed_password: $hashed_password,
    full_name: $full_name,
    created_at: datetime()
})
RETURN a
"""

GET_ACCOUNT_BY_EMAIL = """
MATCH (a:Account {email: $email})
RETURN a
"""

GET_ACCOUNT_BY_ID = """
MATCH (a:Account {id: $id})
RETURN a
"""
