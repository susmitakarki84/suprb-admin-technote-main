/**
 * Express Server for Role-Based Admin Dashboard
 * Handles authentication, user management with role-based access control
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const AuthUser = require('./authSchema');
const { registerUser } = require('./registerRoutes');
const { validateEmail, validatePassword } = require('./validation');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('✅ Connected to MongoDB');
        initializeSuperAdmin();
    })
    .catch(err => console.error('❌ MongoDB connection error:', err));

// Initialize Super Admin Account
async function initializeSuperAdmin() {
    try {
        const superAdminEmail = 'sup_admin_enter@gmail.com';
        const superAdminPassword = 'admin1234@ADmin_super_B';

        const existingAdmin = await AuthUser.findOne({ email: superAdminEmail });

        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(superAdminPassword, 10);
            const superAdmin = new AuthUser({
                email: superAdminEmail,
                password: hashedPassword,
                role: 'superadmin'
            });
            await superAdmin.save();
            console.log('✅ Super Admin account created');
        } else {
            // Update existing admin to superadmin role if needed
            if (existingAdmin.role !== 'superadmin') {
                existingAdmin.role = 'superadmin';
                await existingAdmin.save();
                console.log('✅ Super Admin role updated');
            } else {
                console.log('✅ Super Admin account already exists');
            }
        }
    } catch (error) {
        console.error('❌ Error initializing super admin:', error);
    }
}

// JWT Middleware for protected routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Role-based authorization middleware
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. No role assigned.'
            });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. Required role: ${allowedRoles.join(' or ')}`
            });
        }

        next();
    };
}

// Routes

// Registration Route
app.post('/api/register', registerUser);

// Login Route with Brute Force Protection
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        // Find user
        const user = await AuthUser.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Only allow superadmin login
        if (user.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Only superadmin users can login to this portal.'
            });
        }

        // Check if user is locked out
        const lockoutDuration = 15 * 60 * 1000; // 15 minutes in milliseconds
        const maxAttempts = 5;

        if (user.lockoutUntil && user.lockoutUntil > new Date()) {
            const remainingTime = Math.ceil((user.lockoutUntil - new Date()) / 1000);
            return res.status(429).json({
                success: false,
                message: 'Too many failed attempts. Please try again later.',
                lockout: true,
                remainingTime: remainingTime // in seconds
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            // Increment failed attempts
            user.failedLoginAttempts += 1;

            // Lock user out if max attempts reached
            if (user.failedLoginAttempts >= maxAttempts) {
                user.lockoutUntil = new Date(Date.now() + lockoutDuration);
            }

            await user.save();

            const remainingAttempts = Math.max(0, maxAttempts - user.failedLoginAttempts);
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password',
                remainingAttempts: remainingAttempts
            });
        }

        // Reset failed attempts on successful login
        user.failedLoginAttempts = 0;
        user.lockoutUntil = null;
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            token: token,
            user: {
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

// Get All Users (Super Admin and Admin)
app.get('/api/users', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        let users;

        if (req.user.role === 'superadmin') {
            // Super admin can see all users
            users = await AuthUser.find({}, { password: 0 }).sort({ createdAt: -1 });
        } else if (req.user.role === 'admin') {
            // Admin can only see users with 'user' role
            users = await AuthUser.find({ role: 'user' }, { password: 0 }).sort({ createdAt: -1 });
        }

        res.json({
            success: true,
            users: users
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error fetching users'
        });
    }
});

// Update User Password (Super Admin and Admin with restrictions)
app.put('/api/users/:userId/password', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({
                success: false,
                message: 'New password is required'
            });
        }

        if (!validatePassword(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        // Get the target user
        const targetUser = await AuthUser.findById(userId);
        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Role-based restrictions
        if (req.user.role === 'admin') {
            // Admin can only change passwords of regular users
            if (targetUser.role !== 'user') {
                return res.status(403).json({
                    success: false,
                    message: 'Admins can only change passwords of regular users'
                });
            }
        }

        // Prevent changing super admin password unless you are super admin
        if (targetUser.role === 'superadmin' && req.user.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot change super admin password'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        targetUser.password = hashedPassword;
        await targetUser.save();

        res.json({
            success: true,
            message: 'Password updated successfully'
        });

    } catch (error) {
        console.error('Update password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error updating password'
        });
    }
});

// Delete User (Super Admin and Admin with restrictions)
app.delete('/api/users/:userId', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        const { userId } = req.params;

        // Get the target user
        const targetUser = await AuthUser.findById(userId);
        if (!targetUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent deleting super admin account
        if (targetUser.role === 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot delete super admin account'
            });
        }

        // Admin can only delete regular users
        if (req.user.role === 'admin' && targetUser.role !== 'user') {
            return res.status(403).json({
                success: false,
                message: 'Admins can only delete regular users'
            });
        }

        await AuthUser.findByIdAndDelete(userId);

        res.json({
            success: true,
            message: 'User deleted successfully'
        });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error deleting user'
        });
    }
});

// Add New User (Super Admin and Admin with restrictions)
app.post('/api/users', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        const { email, password, role } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required'
            });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid email format'
            });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        // Role validation - only allow admin and user roles (superadmin can only be the original one)
        const validRoles = ['admin', 'user'];
        const userRole = role || 'user';

        if (!validRoles.includes(userRole)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be: admin or user'
            });
        }

        // Role-based restrictions
        if (req.user.role === 'admin') {
            // Admin can only create regular users
            if (userRole !== 'user') {
                return res.status(403).json({
                    success: false,
                    message: 'Admins can only create regular users'
                });
            }
        }

        // Only super admin can create admin accounts
        if (userRole === 'admin' && req.user.role !== 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Only super admin can create admin accounts'
            });
        }

        // Prevent creating new super admin - only one super admin allowed
        if (userRole === 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot create new super admin. Only one super admin is allowed.'
            });
        }

        const existingUser = await AuthUser.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new AuthUser({
            email: email.toLowerCase(),
            password: hashedPassword,
            role: userRole
        });

        await newUser.save();

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: {
                _id: newUser._id,
                email: newUser.email,
                role: newUser.role,
                createdAt: newUser.createdAt
            }
        });

    } catch (error) {
        console.error('Add user error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error creating user'
        });
    }
});

// Update User Role (Super Admin Only)
app.put('/api/users/:userId/role', authenticateToken, authorizeRoles('superadmin'), async (req, res) => {
    try {
        const { userId } = req.params;
        const { role } = req.body;

        const validRoles = ['admin', 'user'];
        if (!role || !validRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role. Must be: admin or user'
            });
        }

        const user = await AuthUser.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent changing the original super admin's role
        if (user.email === 'sup_admin_enter@gmail.com') {
            return res.status(403).json({
                success: false,
                message: 'Cannot change the original super admin role'
            });
        }

        // Prevent setting any user to superadmin role
        if (role === 'superadmin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot set user to super admin role. Only one super admin is allowed.'
            });
        }

        user.role = role;
        await user.save();

        res.json({
            success: true,
            message: 'User role updated successfully',
            user: {
                _id: user._id,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error updating role'
        });
    }
});

// File Upload Route (Multer setup)
const multer = require('multer');
const fs = require('fs');

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExt = path.extname(file.originalname);
        const fileName = path.basename(file.originalname, fileExt) + '-' + uniqueSuffix + fileExt;
        cb(null, fileName);
    }
});

// File upload middleware
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB file size limit
    },
    fileFilter: function (req, file, cb) {
        // Allow only specific file types
        const allowedTypes = [
            'text/csv',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/json'
        ];

        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only CSV, Excel, and JSON files are allowed.'));
        }
    }
});

// File upload endpoint
app.post('/api/upload', authenticateToken, authorizeRoles('superadmin', 'admin'), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }

        res.json({
            success: true,
            message: 'File uploaded successfully',
            filename: req.file.originalname,
            path: req.file.path,
            size: req.file.size
        });

    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during file upload'
        });
    }
});

// Get uploaded files endpoint
app.get('/api/uploads', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        const files = fs.readdirSync(uploadsDir);
        const fileDetails = files.map(file => {
            const filePath = path.join(uploadsDir, file);
            const stat = fs.statSync(filePath);
            return {
                filename: file,
                path: filePath,
                size: stat.size,
                createdAt: stat.birthtime,
                modifiedAt: stat.mtime
            };
        });

        res.json({
            success: true,
            files: fileDetails
        });

    } catch (error) {
        console.error('Get files error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error fetching files'
        });
    }
});

// Delete uploaded file endpoint
app.delete('/api/uploads/:filename', authenticateToken, authorizeRoles('superadmin', 'admin'), async (req, res) => {
    try {
        const { filename } = req.params;
        const filePath = path.join(uploadsDir, filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                message: 'File not found'
            });
        }

        fs.unlinkSync(filePath);

        res.json({
            success: true,
            message: 'File deleted successfully'
        });

    } catch (error) {
        console.error('Delete file error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error deleting file'
        });
    }
});

// Logout Route
app.get('/api/logout', authenticateToken, (req, res) => {
    // Since we're using JWT with localStorage, logout is handled client-side
    // This endpoint is provided for consistency
    res.json({
        success: true,
        message: 'Logout successful'
    });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
