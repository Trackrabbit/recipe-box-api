# Responsibilities in app.py

User registration and login
JWT token creation and validation
Recipe CRUD routes
Low-level DB connection and queries
App configuration / secrets

Total responsibilities: 5

# Target layout

auth_*.py → authentication and authorization
recipes_*.py → all recipe endpoints
db_*.py → DB connections/creation
config_*.py → app config (startup, port, secrets, etc.)

# Acceptance list

POST /register → 201 on success, 400 on bad input
POST /login → 200 + JWT on success, 401 on bad credentials
GET /recipes → 200 + list of recipes (auth required)
POST /recipes → 201 on success (auth required)
GET /recipes/<id> → 200 if found, 404 if not
PUT /recipes/<id> → 200 on success, 403 if not owner, 404 if not found
DELETE /recipes/<id> → 204 on success, 403 if not owner, 404 if not found

# Notes

Hard to find routes and auth logic in a single file.
Importing app runs startup code.