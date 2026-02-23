# Role-Based Access Control (RBAC) Documentation

## 🎯 Overview

This system implements a comprehensive three-tier role-based access control system with the following roles:

1. **Super Admin** - Full system access
2. **Admin** - Limited administrative access
3. **User** - Basic access only

---

## 👥 User Roles

### 1. Super Admin (`superadmin`)

**Full Privileges:**
- ✅ View all users (Super Admins, Admins, and Users)
- ✅ Create users with any role (Super Admin, Admin, or User)
- ✅ Change any user's password
- ✅ Change any user's role
- ✅ Delete any user (except other Super Admins)
- ✅ Access all dashboard features

**Default Super Admin:**
- Email: `sup_admin_enter@gmail.com`
- Password: `admin1234@ADmin_super_B`
- Role: `superadmin`

### 2. Admin (`admin`)

**Limited Privileges:**
- ✅ View only regular users (cannot see Super Admins or other Admins)
- ✅ Create only regular users (role: `user`)
- ✅ Change passwords of regular users only
- ✅ Delete regular users only
- ❌ Cannot create Admin or Super Admin accounts
- ❌ Cannot modify Admin or Super Admin accounts
- ❌ Cannot change user roles

### 3. User (`user`)

**Basic Access:**
- ❌ No dashboard access
- ❌ No administrative privileges
- ❌ Cannot manage other users

---

## 🔐 Authentication & Authorization

### Login Process

1. User enters email and password
2. Server validates credentials
3. JWT token is generated with user's role
4. Token is stored in localStorage
5. User is redirected to dashboard (if Admin or Super Admin)

### Authorization Middleware

```javascript
// Role-based authorization
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied' 
            });
        }
        next();
    };
}
```

---

## 📊 API Endpoints & Permissions

### Authentication Endpoints

| Endpoint | Method | Access | Description |
|----------|--------|--------|-------------|
| `/api/login` | POST | Public | User login |
| `/api/register` | POST | Public | User registration |

### User Management Endpoints

| Endpoint | Method | Super Admin | Admin | User |
|----------|--------|-------------|-------|------|
| `GET /api/users` | GET | ✅ All users | ✅ Users only | ❌ |
| `POST /api/users` | POST | ✅ Any role | ✅ User role only | ❌ |
| `PUT /api/users/:id/password` | PUT | ✅ Anyone | ✅ Users only | ❌ |
| `PUT /api/users/:id/role` | PUT | ✅ | ❌ | ❌ |
| `DELETE /api/users/:id` | DELETE | ✅ (not SA) | ✅ Users only | ❌ |

---

## 🎨 Dashboard UI Features

### Super Admin Dashboard

**Visible Features:**
- User list with all roles
- "Add New User" button with role selection dropdown
- "Change Role" button for each user
- "Change Password" button for all users
- "Delete" button for Admins and Users

**Role Selection Dropdown:**
```html
<select id="newUserRole">
    <option value="user">User</option>
    <option value="admin">Admin</option>
    <option value="superadmin">Super Admin</option>
</select>
```

### Admin Dashboard

**Visible Features:**
- User list (regular users only)
- "Add New User" button (no role selection - defaults to User)
- "Change Password" button for regular users
- "Delete" button for regular users

**Hidden Features:**
- Role selection dropdown
- Change role button
- Actions for Admin/Super Admin accounts

---

## 🔒 Security Rules

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

### Role Assignment Rules

1. **Super Admin Creation:**
   - Only Super Admin can create other Super Admins
   - Original Super Admin cannot have role changed

2. **Admin Creation:**
   - Only Super Admin can create Admins
   - Admins cannot create other Admins

3. **User Creation:**
   - Both Super Admin and Admin can create Users
   - Default role for new users is `user`

### Modification Rules

1. **Super Admin Protection:**
   - Cannot delete Super Admin accounts
   - Cannot change original Super Admin's role
   - Only Super Admin can modify Super Admin accounts

2. **Admin Restrictions:**
   - Can only view/modify regular users
   - Cannot see or modify other Admins
   - Cannot see or modify Super Admins

3. **User Restrictions:**
   - No administrative access
   - Cannot access dashboard

---

## 💾 Database Schema

### AuthUser Model

```javascript
{
    email: String,        // Unique, lowercase, trimmed
    password: String,     // Bcrypt hashed
    role: String,         // 'superadmin', 'admin', or 'user'
    createdAt: Date       // Auto-generated
}
```

### Role Field

```javascript
role: {
    type: String,
    enum: ['superadmin', 'admin', 'user'],
    default: 'user',
    required: true
}
```

---

## 🚀 Usage Examples

### Creating a Super Admin (Super Admin Only)

1. Login as Super Admin
2. Click "Add New User"
3. Enter email and password
4. Select "Super Admin" from role dropdown
5. Click "Create User"

### Creating an Admin (Super Admin Only)

1. Login as Super Admin
2. Click "Add New User"
3. Enter email and password
4. Select "Admin" from role dropdown
5. Click "Create User"

### Creating a User (Super Admin or Admin)

1. Login as Super Admin or Admin
2. Click "Add New User"
3. Enter email and password
4. Select "User" from role dropdown (Super Admin) or it defaults to User (Admin)
5. Click "Create User"

### Changing User Role (Super Admin Only)

1. Login as Super Admin
2. Find the user in the list
3. Click "Change Role"
4. Select new role from dropdown
5. Click "Update Role"

### Changing Password

**Super Admin:**
- Can change anyone's password

**Admin:**
- Can only change regular users' passwords

**Steps:**
1. Find user in list
2. Click "Change Password"
3. Enter new password
4. Click "Update Password"

### Deleting Users

**Super Admin:**
- Can delete Admins and Users (not Super Admins)

**Admin:**
- Can only delete regular Users

**Steps:**
1. Find user in list
2. Click "Delete"
3. Confirm deletion

---

## 🎯 Role-Based UI Behavior

### Login Page
- Displays test credentials
- No role-specific features

### Dashboard Header
- Shows user email and role
- Example: "user@example.com (Super Admin)"

### User Table
- **Super Admin sees:** All users with all action buttons
- **Admin sees:** Only regular users with limited action buttons

### Add User Modal
- **Super Admin:** Role selection dropdown visible
- **Admin:** Role selection hidden (defaults to User)

### Action Buttons
- **Super Admin:** All buttons visible (Change Role, Change Password, Delete)
- **Admin:** Limited buttons (Change Password, Delete for Users only)
- **Disabled:** "No actions available" for users they cannot modify

---

## 🔧 Testing the System

### Test Accounts

1. **Super Admin (Pre-created)**
   - Email: `sup_admin_enter@gmail.com`
   - Password: `admin1234@ADmin_super_B`
   - Role: `superadmin`

2. **Create Test Admin**
   - Login as Super Admin
   - Create user with role: `admin`
   - Test admin restrictions

3. **Create Test User**
   - Login as Admin or Super Admin
   - Create user with role: `user`
   - Verify no dashboard access

### Testing Scenarios

1. **Super Admin Tests:**
   - ✅ Create all role types
   - ✅ View all users
   - ✅ Change any role
   - ✅ Delete Admins and Users

2. **Admin Tests:**
   - ✅ Create only Users
   - ✅ View only Users
   - ❌ Cannot create Admins
   - ❌ Cannot see other Admins
   - ❌ Cannot change roles

3. **User Tests:**
   - ❌ Cannot access dashboard
   - ❌ Redirected to login

---

## 📝 API Response Examples

### Successful Login

```json
{
    "success": true,
    "message": "Login successful",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "email": "sup_admin_enter@gmail.com",
        "role": "superadmin"
    }
}
```

### Get Users (Super Admin)

```json
{
    "success": true,
    "users": [
        {
            "_id": "...",
            "email": "sup_admin_enter@gmail.com",
            "role": "superadmin",
            "createdAt": "2024-01-01T00:00:00.000Z"
        },
        {
            "_id": "...",
            "email": "admin@example.com",
            "role": "admin",
            "createdAt": "2024-01-02T00:00:00.000Z"
        }
    ]
}
```

### Get Users (Admin)

```json
{
    "success": true,
    "users": [
        {
            "_id": "...",
            "email": "user@example.com",
            "role": "user",
            "createdAt": "2024-01-03T00:00:00.000Z"
        }
    ]
}
```

### Access Denied

```json
{
    "success": false,
    "message": "Access denied. Required role: superadmin or admin"
}
```

---

## 🛡️ Security Best Practices

1. **JWT Tokens:**
   - 24-hour expiration
   - Stored in localStorage
   - Included in Authorization header

2. **Password Security:**
   - Bcrypt hashing with 10 salt rounds
   - Never stored in plain text
   - Strong password requirements enforced

3. **Role Validation:**
   - Server-side validation on all endpoints
   - Client-side UI adjustments for UX
   - Cannot bypass role restrictions

4. **Super Admin Protection:**
   - Original Super Admin cannot be deleted
   - Original Super Admin role cannot be changed
   - Prevents system lockout

---

## 📚 Summary

This role-based access control system provides:

- ✅ Three distinct user roles with clear permissions
- ✅ Secure authentication with JWT tokens
- ✅ Role-based API authorization
- ✅ Dynamic UI based on user role
- ✅ Comprehensive security measures
- ✅ Protection against unauthorized access
- ✅ Flexible user management for Super Admins
- ✅ Restricted but functional access for Admins
- ✅ Complete isolation for regular Users

The system ensures that each role has appropriate access levels while maintaining security and preventing privilege escalation.
