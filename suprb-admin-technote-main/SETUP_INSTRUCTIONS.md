# Super Admin Dashboard - Setup Instructions

## 🚀 Overview

This is a complete Super Admin Dashboard system with secure authentication and user management capabilities.

### Super Admin Credentials
- **Email:** `sup_admin_enter@gmail.com`
- **Password:** `admin1234@ADmin_super_B`

⚠️ **IMPORTANT:** These credentials are automatically created when the server starts for the first time.

---

## 📋 Features

✅ **Secure Authentication**
- Bcrypt password hashing
- JWT token-based authentication
- Protected API routes

✅ **User Management**
- View all registered users
- Add new users
- Change user passwords
- Delete users (except super admin)
- Role-based access control

✅ **User Registration**
- Public registration page for new users
- Password strength validation
- Email validation

---

## 🛠️ Installation Steps

### 1. Install Dependencies

```bash
npm install
```

This will install:
- express
- mongoose
- bcrypt
- jsonwebtoken
- cors
- dotenv

### 2. Configure Environment Variables

The `.env` file is already configured with:
```
MONGO_URI="mongodb+srv://note-app:noteapp1234@note-app.sweo75m.mongodb.net/"
PORT=5000
JWT_SECRET="your-super-secret-jwt-key-change-this-in-production-2024"
```

⚠️ **Security Note:** In production, change the JWT_SECRET to a strong, unique value.

### 3. Start the Server

```bash
npm start
```

Or for development with auto-restart:
```bash
npm run dev
```

The server will start on `process.port.envBACKEND_API`;

---

## 📁 File Structure

```
superb_admin/
├── server.js                      # Express server with all API routes
├── authSchema.js                  # MongoDB user schema
├── registerRoutes.js              # Registration API logic
├── validation.js                  # Email and password validation
├── .env                           # Environment variables
├── package.json                   # Dependencies
│
├── index.html                     # User registration page
├── register.css                   # Registration page styles
├── register.js                    # Registration page logic
│
├── login.html                     # Super admin login page
├── login.css                      # Login page styles
├── login.js                       # Login page logic
│
├── superb_admin_dashboard.html    # Admin dashboard
├── dashboard.css                  # Dashboard styles
└── dashboard.js                   # Dashboard logic
```

---

## 🔐 How to Use

### Step 1: Start the Server
```bash
npm start
```

### Step 2: Access the Login Page
Open your browser and go to:
```
http://localhost:5000/login.html
```

### Step 3: Login as Super Admin
Use the credentials:
- Email: `sup_admin_enter@gmail.com`
- Password: `admin1234@ADmin_super_B`

### Step 4: Manage Users
After successful login, you'll be redirected to the dashboard where you can:
- View all registered users
- Add new users
- Change user passwords
- Delete users

---

## 👥 User Registration

Regular users can register at:
```
http://localhost:5000/index.html
```

After registration, they can login at the login page, but they won't have access to the admin dashboard (only super admin has access).

---

## 🔒 Security Features

1. **Password Hashing:** All passwords are hashed using bcrypt with 10 salt rounds
2. **JWT Authentication:** Secure token-based authentication with 24-hour expiration
3. **Protected Routes:** All admin API routes require valid JWT token
4. **Role-Based Access:** Only super admin can access user management features
5. **Super Admin Protection:** Super admin account cannot be deleted
6. **Password Validation:** Enforces strong password requirements:
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number

---

## 🌐 API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login user

### User Management (Super Admin Only)
- `GET /api/users` - Get all users
- `POST /api/users` - Add new user
- `PUT /api/users/:userId/password` - Change user password
- `DELETE /api/users/:userId` - Delete user

All user management endpoints require:
```
Authorization: Bearer <JWT_TOKEN>
```

---

## 🐛 Troubleshooting

### Server won't start
- Check if MongoDB connection string is correct in `.env`
- Ensure port 5000 is not already in use
- Run `npm install` to ensure all dependencies are installed

### Can't login
- Ensure the server is running
- Check browser console for errors
- Verify credentials are correct

### Database connection error
- Check MongoDB URI in `.env`
- Ensure MongoDB cluster is accessible
- Check network connection

---

## 📝 Notes

- The super admin account is automatically created on first server start
- All passwords are securely hashed and never stored in plain text
- JWT tokens expire after 24 hours
- The dashboard automatically checks authentication on page load
- Users are automatically redirected to login if not authenticated

---

## 🎯 Quick Start Summary

1. Run `npm install`
2. Run `npm start`
3. Open `http://localhost:/login.html`
4. Login with: `sup_admin_enter@gmail.com` / `admin1234@ADmin_super_B`
5. Manage users from the dashboard!

---

## 📞 Support

If you encounter any issues, check:
1. Server console for error messages
2. Browser console for client-side errors
3. MongoDB connection status
4. Network connectivity

---

**Enjoy managing your users! 🎉**
