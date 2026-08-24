# SecureSphere Enterprise Identity & Access Management

SecureSphere is a full-stack Identity and Access Management (IAM) application for managing users, roles, permissions, multi-factor authentication (MFA), and security audit logs.

The project uses a vanilla HTML/CSS/JavaScript frontend, an Express.js REST API, and PostgreSQL.

## Features

- User registration and JWT-based login
- Password hashing with bcrypt
- Role-based access control (RBAC) using roles and permissions
- User administration: list, create, update, delete, and assign roles
- Time-based one-time password (TOTP) MFA with QR-code setup
- MFA-aware login flow with temporary MFA tokens
- Security audit logging and audit-log filtering
- HTTP security headers, CORS rules, and API rate limiting
- PostgreSQL schema and Docker Compose database setup

## Technology stack

| Layer | Technologies |
| --- | --- |
| Frontend | HTML, CSS, JavaScript, Fetch API |
| Backend | Node.js, Express 5 |
| Database | PostgreSQL 16 |
| Authentication | JSON Web Tokens (`jsonwebtoken`) |
| MFA | `speakeasy`, `qrcode` |
| Security | `bcryptjs`, Helmet, CORS, express-rate-limit |
| Database access | `pg` |
| Local database container | Docker Compose |

## Project structure

```text
Enterprise-Identity-IAM/
├── backend/
│   ├── .env.example                 # Environment-variable template
│   ├── package.json                 # Node.js dependencies and scripts
│   ├── package-lock.json
│   └── src/
│       ├── config/
│       │   └── database.js           # PostgreSQL connection pool
│       ├── controllers/
│       │   ├── auditController.js    # Audit-log retrieval and summary
│       │   ├── authController.js     # Registration and login
│       │   ├── mfaController.js      # TOTP setup, verification, disablement
│       │   ├── roleController.js     # Roles and role assignment
│       │   └── userController.js     # User profile and user management
│       ├── middleware/
│       │   └── authMiddleware.js     # JWT and permission authorization
│       ├── routes/
│       │   ├── auditRoutes.js
│       │   ├── authRoutes.js
│       │   ├── mfaRoutes.js
│       │   ├── roleRoutes.js
│       │   └── userRoutes.js
│       ├── utils/
│       │   └── auditLogger.js        # Audit-log helper
│       └── server.js                 # Express application entry point
├── database/
│   └── schema.sql                    # IAM database tables and relationships
├── frontend/
│   ├── audit.html                    # Audit-log viewer
│   ├── dashboard.html                # Dashboard and user administration
│   ├── login.html                    # Login and registration page
│   ├── mfa.html                      # MFA setup and MFA login verification
│   └── users.html                    # User-management page
├── docs/                             # Project documentation (currently empty)
├── docker-compose.yml                # PostgreSQL 16 service
├── .gitignore
└── README.md
```

## Prerequisites

- Node.js 18 or later
- npm
- Docker Desktop and Docker Compose, or a local PostgreSQL instance
- A TOTP authenticator application, such as Google Authenticator, Microsoft Authenticator, or Authy

## Getting started

### 1. Start PostgreSQL

From the project root:

```bash
docker compose up -d
```

This starts PostgreSQL on port `5432`, creates the `enterprise_iam` database, and applies `database/schema.sql` only when the Docker volume is first initialized.

### 2. Configure the backend

Create `backend/.env` by copying `backend/.env.example`, then set a strong JWT secret:

```env
PORT=5000
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/enterprise_iam
JWT_SECRET=replace-with-a-long-random-secret
JWT_EXPIRES_IN=1h
CLIENT_ORIGIN=http://localhost:5500
```

> The active CORS allow-list in `backend/src/server.js` permits `http://localhost:5500` and `http://127.0.0.1:5500`.

### 3. Install and run the API

```bash
cd backend
npm install
npm run dev
```

The API runs at `http://localhost:5000`. Verify it with:

```text
GET http://localhost:5000/api/health
```

### 4. Serve the frontend

Serve the `frontend` folder using a static server on port `5500`, then open `login.html` in the browser. For example, VS Code Live Server can serve this folder on the allowed port.

The frontend is configured to call `http://localhost:5000`.

## Initial access and RBAC data

Registration creates a user account but does not assign a role. Administrative routes require permissions such as `USER_READ`, `USER_CREATE`, `ROLE_READ`, and `AUDIT_READ`.

Before using protected management screens, insert at least one role, the corresponding permissions, and a `user_roles` / `role_permissions` mapping in PostgreSQL. The schema defines these tables but does not include seed data or a default administrator.

## API overview

All protected routes require an `Authorization: Bearer <token>` header. Permission-protected routes also require the listed RBAC permission.

| Method | Endpoint | Purpose | Required permission |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | Register a user | — |
| POST | `/api/auth/login` | Log in; may return an MFA token | — |
| POST | `/api/mfa/setup` | Generate a TOTP secret and QR code | Authenticated user |
| POST | `/api/mfa/verify` | Verify MFA setup or an MFA login | JWT or temporary MFA token |
| DELETE | `/api/mfa/disable` | Disable MFA | `MFA_DISABLE` |
| GET | `/api/users/me` | Get current user, role, and permissions | Authenticated user |
| GET | `/api/users` | List users | `USER_READ` |
| POST | `/api/users` | Create a user | `USER_CREATE` |
| PUT | `/api/users/:userId` | Update a user | `USER_UPDATE` |
| DELETE | `/api/users/:userId` | Delete a user | `USER_DELETE` |
| POST | `/api/users/:userId/role` | Replace a user's role | `ROLE_ASSIGN` |
| GET | `/api/roles` | List roles | `ROLE_READ` |
| GET | `/api/audit-logs` | Retrieve audit logs | `AUDIT_READ` |
| GET | `/api/audit-logs/summary` | Retrieve audit summary | `AUDIT_READ` |
| GET | `/api/health` | API and database health check | — |

Audit logs accept optional query parameters: `action`, `result`, `riskLevel`, `userId`, `startDate`, `endDate`, `limit`, and `offset`.

## Security notes

- Do not commit `backend/.env` or a production JWT secret.
- Use a strong database password and `JWT_SECRET` outside local development.
- The current MFA secret is stored directly in the database column named `secret_encrypted`; encrypt it with a managed key before production use.
- Serve the frontend and API over HTTPS in production, and restrict CORS to approved origins.

## Useful commands

```bash
# Start the database
docker compose up -d

# Stop the database
docker compose down

# Run the API in development mode
cd backend
npm run dev

# Run the API normally
npm start
```
