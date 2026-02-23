/**
 * Authentication User Schema
 * MongoDB schema for storing user authentication data
 */

const mongoose = require('mongoose');

const AuthUserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['superadmin', 'admin', 'user'],
        default: 'user',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    lockoutUntil: {
        type: Date,
        default: null
    }
});



const AuthUser = mongoose.model('AuthUser', AuthUserSchema);

module.exports = AuthUser;
