# Security Audit – Recipe API

## 1. Safe password storage

- **DB:** SQLite (`recipes.db`)
- **Query:**
  - `SELECT id, email, password_hash FROM users LIMIT 5;`
- **Observation:**
  - `password_hash` uses `pbkdf2:sha256` with iterations and salt.
  - No plaintext passwords in the `users` table.

**Conclusion:** Passwords are stored as secure hashes, not plaintext.

---

## 2. Authentication and authorization – GET /recipes/:id

Tested against `http://localhost:5001`.

### Cases

- Public recipe (`id=4`, owner_id=1), no token  
  - Request: `GET /recipes/4`  
  - Result: `200 OK`, recipe JSON returned.  

- Private recipe (`id=3`, is_public=false, owner_id=1), no token  
  - Request: `GET /recipes/3`  
  - Result: `401 UNAUTHORIZED`, `"authentication required for private recipe"`.

- Private recipe (`id=3`), invalid token  
  - Request: `GET /recipes/3` with `Authorization: Bearer totally.invalid.token`  
  - Result: `401 UNAUTHORIZED`, `"invalid token"`.

- Private recipe (`id=3`), Bob token (`sub=2`, role=user, non-owner)  
  - Request: `GET /recipes/3` with Bob’s token  
  - Result: `403 FORBIDDEN`, `"forbidden: not the recipe owner"`.

- Private recipe (`id=3`), Alice token (`sub=1`, role=admin, owner)  
  - Request: `GET /recipes/3` with Alice’s token  
  - Result: `200 OK`, private recipe JSON.

**Conclusion:** Public vs private visibility and owner-only access are enforced correctly with proper `401` vs `403` behavior.

---

## 3. Authentication and authorization – DELETE /recipes/:id

Tested with recipe `id=5` (originally public, owner_id=2 – Bob):

- Anonymous delete  
  - Request: `DELETE /recipes/5` (no token)  
  - Result: `401 UNAUTHORIZED`, `"authentication required"`.

- Owner delete (Bob)  
  - Request: `DELETE /recipes/5` with Bob’s token (`sub=2`, role=user)  
  - Result: `204 NO CONTENT`.

- Verify deletion  
  - Request: `GET /recipes/5`  
  - Result: `404 NOT FOUND`, `"recipe not found"`.

**Conclusion:** Delete requires authentication; owners can delete their own recipes, and deletion persists in the database.

---

## 4. Historical exploit replay – cross-user delete

Previous risk: a user might delete another user’s recipe by calling `DELETE /recipes/:id` with a non-owner token.

Current test:

- Attack: Bob (user 2) attempts to delete Alice’s private recipe (`id=3`, owner_id=1).  
  - Request: `DELETE /recipes/3` with Bob’s token (`sub=2`, role=user)  
  - Result: `403 FORBIDDEN`, `"forbidden: not the recipe owner or admin"`.

- Follow-up: check recipe still exists (requires auth because it’s private).  
  - Request: `GET /recipes/3` with valid owner/admin token (`sub=1`)  
  - Result: `200 OK`, recipe JSON still present.

**Conclusion:** Former cross-user delete exploit is blocked; non-owners cannot delete other users’ recipes.

---

## 5. Centralized authentication and trusted ownership

- All protected routes (e.g. `DELETE /recipes/:id`) use the shared `@require_auth` decorator.
- `require_auth`:
  - Validates JWTs and returns `401` on missing/invalid/expired tokens.
  - Stores identity on `g.current_user_id` and `g.current_is_admin`.
- Authorization checks (e.g. delete) use `owner_id` from the database and `g.current_user_id` / `g.current_is_admin`, not client-supplied ownership data.

**Conclusion:** Authentication is centralized in middleware, and authorization decisions rely on trusted stored data.