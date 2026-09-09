# 🔐 SecureSphere Enterprise IAM

**SecureSphere Enterprise IAM** is a secure, scalable **Enterprise Identity and Access Management (IAM)** system designed to manage users, roles, permissions, authentication, multi-factor authentication, and security audit logs.

The system provides **JWT-based authentication, Role-Based Access Control (RBAC), TOTP-based MFA, backup codes, audit logging, account security, and PostgreSQL database integration**.

---

## 🚀 Live Demo

### 🌐 Frontend

**SecureSphere IAM:**
[https://securesphereiam.netlify.app](https://securesphereiam.netlify.app)

### ⚙️ Backend API

**Enterprise IAM API:**
[https://enterprise-identity-iam.onrender.com](https://enterprise-identity-iam.onrender.com)

### 💻 GitHub Repository

[https://github.com/vamsi-bear/Enterprise-Identity-IAM](https://github.com/vamsi-bear/Enterprise-Identity-IAM)

---

## 📌 Project Overview

Modern enterprise applications require secure identity management to control who can access applications, what resources they can access, and what actions they are allowed to perform.

SecureSphere Enterprise IAM provides a centralized platform for:

- 👤 User Management
- 🔑 Secure Authentication
- 🛡️ Role-Based Access Control
- 🔐 Multi-Factor Authentication
- 🎫 JWT-Based Authorization
- 🔑 MFA Backup Codes
- 📋 Audit Logging
- 🔒 Account Locking and Security Controls
- 🗄️ PostgreSQL Database Management
- 🌐 RESTful API Architecture

The project follows a modular backend architecture using **Node.js and Express.js**, with **PostgreSQL** as the relational database.

---

# ✨ Features

## 👤 User Management

Administrators can manage users through the IAM dashboard.

Supported operations:

- View users
- Create users
- Update users
- Delete users
- Assign roles
- View user account status
- Manage authentication status

---

## 🔑 Authentication

Secure authentication is implemented using:

- Email/password authentication
- Password hashing
- JSON Web Tokens (JWT)
- Authentication middleware
- Account status validation
- Failed login tracking
- Account locking support

Authentication flow:
```text
User
 │
 ▼
Email + Password
 │
 ▼
Backend Authentication
 │
 ├── Invalid → Access Denied
 │
 └── Valid
       │
       ▼
   MFA Required?
       │
   ┌───┴────┐
   │        │
  Yes       No
   │        │
   ▼        ▼
 MFA       JWT
   │
   ▼
Final JWT
   │
   ▼
Dashboard
```

---

# 🔐 Multi-Factor Authentication

SecureSphere supports **TOTP-based Multi-Factor Authentication**.

Compatible authenticator applications include:

- Google Authenticator
- Microsoft Authenticator

### MFA Setup
```text
Login
  ↓
Enable MFA
  ↓
Generate Secret
  ↓
Generate QR Code
  ↓
Scan using Authenticator App
  ↓
Enter 6-digit TOTP
  ↓
Verify
  ↓
MFA Enabled
```

---

## 🔑 MFA Backup Codes

Users can generate backup codes in case they cannot access their authenticator application.

Features:

- Generate backup codes
- Each code can be used only once
- Previous codes are invalidated when new codes are generated
- Backup codes are stored as hashes
- Backup-code authentication generates a final authenticated JWT
- Remaining backup-code count is tracked

Example:
```text
Backup Code
     ↓
Hash Code
     ↓
Compare with Database
     ↓
Valid?
 ┌───┴────┐
Yes       No
 │         │
 ▼         ▼
Mark      Reject
Used      Login
 │
 ▼
Generate JWT
 │
 ▼
Dashboard
```

---

# 🛡️ Role-Based Access Control

SecureSphere uses **RBAC** to control access to protected resources.

## Available Roles

| Role          | Description                |
| ------------- | -------------------------- |
| `EMPLOYEE`    | Standard employee access   |
| `DEVELOPER`   | Developer-level access     |
| `ADMIN`       | Administrative access      |
| `SUPER_ADMIN` | Full administrative access |

---

## 🔑 Permissions

The system supports the following permissions:

| Permission    | Description     |
| ------------- | --------------- |
| `USER_READ`   | View users      |
| `USER_CREATE` | Create users    |
| `USER_UPDATE` | Update users    |
| `USER_DELETE` | Delete users    |
| `ROLE_ASSIGN` | Assign roles    |
| `AUDIT_READ`  | View audit logs |

---

## RBAC Model
```text
User
 │
 ▼
User Role
 │
 ▼
Role
 │
 ▼
Role Permissions
 │
 ▼
Permission
 │
 ▼
Protected API Resource
```

Example:
```text
ADMIN
 │
 ├── USER_READ
 ├── USER_CREATE
 ├── USER_UPDATE
 ├── USER_DELETE
 ├── ROLE_ASSIGN
 └── AUDIT_READ
```

---

# 📋 Audit Logging

SecureSphere records important security and administrative events.

Examples include:

- Login attempts
- MFA verification
- MFA failures
- Backup-code generation
- Backup-code authentication
- Role assignments
- User management actions
- Access-denied events

Audit logs contain information such as:
```text
User
Action
Resource
Resource ID
Result
Risk Level
IP Address
User Agent
Metadata
Timestamp
```

Possible results:
```text
SUCCESS
FAILED
DENIED
```

Risk levels:
```text
LOW
MEDIUM
HIGH
CRITICAL
```

---

# 🔒 Security Features

SecureSphere includes several security mechanisms:

- 🔐 JWT authentication
- 🔑 Password hashing
- 🛡️ Role-Based Access Control
- 🔒 Multi-Factor Authentication
- 🎫 MFA backup codes
- 🪪 Authorization middleware
- 🛡️ Helmet security headers
- 🌐 CORS protection
- 🚦 API rate limiting
- 🔐 Account locking
- 📋 Audit logging
- 🗄️ Parameterized PostgreSQL queries
- 🔑 Environment-based secrets

---

# 🏗️ System Architecture
```text
                    ┌──────────────────────┐
                    │      User Browser    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Netlify Frontend   │
                    │   HTML / CSS / JS     │
                    └──────────┬───────────┘
                               │
                         HTTPS / REST
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Render Backend    │
                    │ Node.js + Express.js  │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       Authentication       RBAC/MFA       Audit Logging
              │                │                │
              └────────────────┼────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ PostgreSQL Database  │
                    └──────────────────────┘
```

---

# 🧰 Technologies Used

## Frontend

- HTML5
- CSS3
- JavaScript
- Responsive Web Design
- Fetch API
- Local Storage

## Backend

- Node.js
- Express.js
- JWT
- bcrypt
- Speakeasy
- QRCode
- Helmet
- CORS
- express-rate-limit

## Database

- PostgreSQL
- UUID
- JSONB
- Foreign Keys
- Constraints
- Transactions

## Development Tools

- Visual Studio Code
- Git
- GitHub
- npm
- Nodemon
- PostgreSQL
- Postman / cURL

## Deployment

- Netlify — Frontend
- Render — Backend
- Render PostgreSQL — Database

---

# 📂 Project Structure
```text
Enterprise-Identity-IAM/
│
├── backend/
│   │
│   ├── src/
│   │   │
│   │   ├── config/
│   │   │   └── database.js
│   │   │
│   │   ├── controllers/
│   │   │   ├── authController.js
│   │   │   ├── mfaController.js
│   │   │   ├── roleController.js
│   │   │   ├── userController.js
│   │   │   └── auditController.js
│   │   │
│   │   ├── middleware/
│   │   │   └── authMiddleware.js
│   │   │
│   │   ├── routes/
│   │   │   ├── authRoutes.js
│   │   │   ├── mfaRoutes.js
│   │   │   ├── userRoutes.js
│   │   │   ├── roleRoutes.js
│   │   │   └── auditRoutes.js
│   │   │
│   │   └── server.js
│   │
│   ├── package.json
│   └── .env
│
├── frontend/
│   ├── login.html
│   ├── mfa.html
│   ├── dashboard.html
│   └── ...
│
├── database/
│   └── schema.sql
│
├── .gitignore
└── README.md
```

---

# 🗄️ Database Design

The PostgreSQL database contains multiple tables for identity, authorization, authentication, and security management.

Main tables:
```text
users
roles
permissions
user_roles
role_permissions
groups
group_members
applications
application_permissions
policies
policy_statements
mfa_credentials
backup_codes
sessions
login_attempts
audit_logs
security_events
```

### Core Relationship
```text
users
  │
  │
  ▼
user_roles
  │
  ▼
roles
  │
  ▼
role_permissions
  │
  ▼
permissions
```

### MFA Relationship
```text
users
 │
 ├── mfa_credentials
 │
 └── backup_codes
```

---

# 🌐 API Endpoints

## Authentication

### Register
```http
POST /api/auth/register
```

### Login
```http
POST /api/auth/login
```

---

## Users

### Get Current User
```http
GET /api/users/me
```

### Get All Users
```http
GET /api/users
```

### Create User
```http
POST /api/users
```

### Update User
```http
PUT /api/users/:userId
```

### Delete User
```http
DELETE /api/users/:userId
```

### Assign Role
```http
PUT /api/users/:userId/role
```

---

## Roles

### Get Roles
```http
GET /api/roles
```

---

## MFA

### Setup MFA
```http
POST /api/mfa/setup
```

### Verify MFA
```http
POST /api/mfa/verify
```

### Verify Login MFA
```http
POST /api/mfa/verify-login
```

### Generate Backup Codes
```http
POST /api/mfa/backup-codes
```

### Verify Backup Code
```http
POST /api/mfa/verify-backup
```

### Disable MFA
```http
DELETE /api/mfa/disable
```

---

## Audit Logs

### Get Audit Logs
```http
GET /api/audit-logs
```

Example:
```http
GET /api/audit-logs?limit=5
```

---

## Health Check
```http
GET /api/health
```

Example response:
```json
{
  "status": "success",
  "message": "Enterprise IAM API is running",
  "database": "connected"
}
```

---

# ⚙️ Local Installation

## 1. Clone the Repository
```bash
git clone https://github.com/vamsi-bear/Enterprise-Identity-IAM.git
```

Navigate into the project:
```bash
cd Enterprise-Identity-IAM
```

---

## 2. Install Backend Dependencies
```bash
cd backend
npm install
```

---

## 3. Configure Environment Variables

Create:
```text
backend/.env
```

Example:
```env
PORT=5000

DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5433/enterprise_iam

JWT_SECRET=YOUR_SECRET_KEY

JWT_EXPIRES_IN=1h

CLIENT_ORIGIN=http://localhost:5500
```

### ⚠️ Important

Never commit `.env` to GitHub.

Your `.gitignore` should contain:
```gitignore
node_modules/
.env
*.log
.DS_Store
Thumbs.db
```

---

# 🗄️ Database Setup

Make sure PostgreSQL is running.

Create the database:
```sql
CREATE DATABASE enterprise_iam;
```

Import the schema:
```bash
psql -U postgres -h localhost -p 5433 -d enterprise_iam -f database/schema.sql
```

If `psql` is not available in PATH on Windows, use:
```cmd
"C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -h localhost -p 5433 -d enterprise_iam -f database\schema.sql
```

---

# ▶️ Run the Backend

From the `backend` directory:
```bash
npm run dev
```

The API will run on:
```text
http://localhost:5000
```

---

# 🌐 Run the Frontend

The frontend consists of static HTML, CSS, and JavaScript files.

You can use:

- VS Code Live Server
- Netlify
- Any static web server

For VS Code Live Server, open:
```text
frontend/login.html
```

and launch it using **Live Server**.

---

# 🧪 Testing

The system can be tested using:

- Browser
- Postman
- cURL
- PostgreSQL CLI

### Authentication Test
```text
Register
   ↓
Login
   ↓
Password Validation
   ↓
MFA
   ↓
JWT
   ↓
Dashboard
```

### RBAC Test
```text
Employee
   ↓
USER_READ
   ↓
Can view users
```
```text
Admin
   ↓
USER_READ
USER_CREATE
USER_UPDATE
USER_DELETE
ROLE_ASSIGN
AUDIT_READ
```

### Backup Code Test
```text
Generate Backup Codes
        ↓
Use Code
        ↓
Authentication Successful
        ↓
Code Marked Used
        ↓
Reuse Same Code
        ↓
Authentication Rejected
```

---

# 🚀 Deployment

## Frontend

The frontend is deployed using **Netlify**.

Production URL:
```text
https://securesphereiam.netlify.app
```

## Backend

The Express.js backend is deployed using **Render**.

Production API:
```text
https://enterprise-identity-iam.onrender.com
```

## Database

PostgreSQL is hosted using Render PostgreSQL.

---

# 🔐 Production Security

For production deployments:

- Never expose `.env` files
- Use strong JWT secrets
- Use HTTPS
- Use secure database credentials
- Enable appropriate CORS origins
- Use rate limiting
- Keep dependencies updated
- Rotate compromised secrets
- Never store plaintext passwords
- Never store plaintext backup codes
- Monitor audit logs
- Use least-privilege access

---

# 📊 Security Model

SecureSphere follows the principle of **least privilege**.
```text
Authentication
      ↓
Identity Verification
      ↓
MFA Verification
      ↓
Authorization
      ↓
Permission Check
      ↓
Resource Access
      ↓
Audit Event
```

A user must successfully authenticate before accessing protected resources, and authorization middleware checks whether the user has the required permission.

---

# 🎯 Project Objectives

The main objectives of SecureSphere Enterprise IAM are:

1. Provide secure centralized authentication.
2. Implement Role-Based Access Control.
3. Provide Multi-Factor Authentication.
4. Provide secure MFA backup mechanisms.
5. Manage enterprise users and roles.
6. Record security and administrative events.
7. Protect APIs using authentication and authorization middleware.
8. Provide a scalable PostgreSQL-based identity architecture.
9. Demonstrate secure full-stack application deployment.

---

# 🔮 Future Enhancements

Possible future improvements include:

- OAuth 2.0 / OpenID Connect
- Google/GitHub login
- WebAuthn / Passkeys
- Email-based account verification
- Password reset functionality
- Advanced policy engine
- Group-based authorization
- Application-level access management
- Session management dashboard
- Security analytics
- Login anomaly detection
- SIEM integration
- Redis-based rate limiting
- Automated security alerts
- Admin notification system

---

# 👨‍💻 Author

**Anga Vamsi**

B.Tech — Computer Science

### GitHub

[https://github.com/vamsi-bear](https://github.com/vamsi-bear)

---

# 📄 License

This project is intended for educational, academic, portfolio, and demonstration purposes.

---

# ⭐ Support

If you find this project useful, consider giving the repository a ⭐ on GitHub.

**SecureSphere Enterprise IAM — Secure Identity. Controlled Access. Trusted Systems.**
