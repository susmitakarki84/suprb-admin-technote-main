const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Import the authentication schema
const Auth = require('./authSchema');

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        console.log('✅ Successfully connected to MongoDB');
    })
    .catch((err) => {
        console.error('❌ Failed to connect to MongoDB:', err);
        process.exit(1);
    });

// Admin user details
const adminUser = {
    email: 'admin@example.com',
    password: 'Admin@123',
    role: 'admin' // Admin role
};

// Create admin user
async function createAdmin() {
    try {
        console.log('🔍 Checking if admin user already exists...');

        // Check if admin user already exists
        const existingAdmin = await Auth.findOne({ email: adminUser.email });
        if (existingAdmin) {
            console.log('ℹ️ Admin user already exists');
            process.exit(0);
        }

        console.log('🔐 Creating admin user...');

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(adminUser.password, saltRounds);

        // Create admin user in the database
        const newAdmin = new Auth({
            email: adminUser.email,
            password: hashedPassword,
            role: adminUser.role
        });

        await newAdmin.save();

        console.log('✅ Admin user created successfully!');
        console.log('📧 Email:', adminUser.email);
        console.log('🔑 Password:', adminUser.password);
        console.log('🎭 Role:', adminUser.role);

        // Disconnect from database
        mongoose.disconnect();
        process.exit(0);
    } catch (error) {
        console.error('❌ Error creating admin user:', error);
        mongoose.disconnect();
        process.exit(1);
    }
}

// Run the function
createAdmin();
