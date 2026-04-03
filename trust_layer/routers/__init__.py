"""Feature routers (v1.4+).

First use of FastAPI APIRouter in this codebase. Each module defines a
`router = APIRouter()` and is registered in app.py via `app.include_router()`.

This pattern keeps feature-scoped routes isolated from the app.py monolith
while remaining purely additive — existing routes in app.py are untouched.
"""
