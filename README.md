# E-Teach Authentication Service

A robust JWT-based authentication service for the E-Teach platform with role-based access control.

## Features

- ✅ User registration and login
- ✅ JWT access tokens (short-lived)
- ✅ JWT refresh tokens (long-lived, HttpOnly cookies)
- ✅ Role-based access control (student/teacher)
- ✅ Password hashing with bcrypt
- ✅ Rate limiting
- ✅ Input validation
- ✅ Security headers
- ✅ CORS configuration
- ✅ MongoDB integration

## Quick Start

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the service**
   ```bash
   # Development
   npm run dev
   
   # Production
   npm start
   ```

## API Endpoints

### Public Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123",
  "role": "student",
  "firstName": "John",
  "lastName": "Doe"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
# Requires refreshToken cookie
```

#### Logout
```http
POST /api/auth/logout
# Clears refreshToken cookie
```

### Protected Endpoints

#### Get Profile
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

#### Verify Token
```http
GET /api/auth/verify
Authorization: Bearer <access_token>
```

## Authentication Flow

1. **Register/Login**: User provides credentials
2. **Token Generation**: Server generates access token (15min) and refresh token (7 days)
3. **Token Storage**: 
   - Access token sent in JSON response
   - Refresh token stored in HttpOnly secure cookie
4. **API Requests**: Include access token in Authorization header
5. **Token Refresh**: Use refresh token to get new access token when expired
6. **Logout**: Clear refresh token from database and cookie

## Middleware Usage

### Protect Routes
```javascript
const { requireAuth } = require('./middleware/auth');
app.get('/protected', requireAuth, (req, res) => {
  // req.user contains: { userId, email, role }
});
```

### Role-Based Protection
```javascript
const { requireAuth, requireTeacher } = require('./middleware/auth');
app.get('/teacher-only', requireAuth, requireTeacher, (req, res) => {
  // Only teachers can access
});
```

## Environment Variables

```env
NODE_ENV=development
PORT=5002
MONGODB_URI=mongodb://localhost:27017/e-teach-auth
ACCESS_TOKEN_SECRET=your-access-token-secret
REFRESH_TOKEN_SECRET=your-refresh-token-secret
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
ALLOWED_ORIGINS=http://localhost:3000
```

## Security Features

- Password hashing with bcrypt (12 rounds)
- JWT tokens with expiration
- HttpOnly secure cookies for refresh tokens
- Rate limiting on authentication endpoints
- Input validation and sanitization
- CORS protection
- Security headers with Helmet
- Role-based access control

## Error Handling

All endpoints return consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "errors": [] // Optional validation errors
}
```

## Database Schema

### User Model
```javascript
{
  email: String (unique, required),
  passwordHash: String (required),
  role: String (enum: ['student', 'teacher']),
  firstName: String (required),
  lastName: String (required),
  refreshToken: String,
  isActive: Boolean,
  lastLogin: Date,
  createdAt: Date,
  updatedAt: Date
}
```
