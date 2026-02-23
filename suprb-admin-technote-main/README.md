# DashboardDemo - User Management Dashboard

## Project Overview

DashboardDemo is a comprehensive user management dashboard application with advanced authentication, user administration, and data management capabilities. Built with modern web technologies, it provides a secure and intuitive interface for managing user accounts and accessing dashboard functionalities.

## Core Technologies

### Backend
- **Node.js**: JavaScript runtime environment
- **Express**: Web application framework for Node.js
- **MongoDB**: NoSQL database for data storage
- **Mongoose**: ODM (Object Data Modeling) library for MongoDB
- **bcrypt**: Password hashing and salting library
- **JWT (jsonwebtoken)**: JSON Web Token implementation for authentication
- **dotenv**: Environment variable management
- **multer**: Middleware for handling file uploads

### Frontend
- **HTML5**: Structure and semantic markup
- **CSS3**: Modern styling with responsive design
- **JavaScript (ES6+)**: Client-side logic and DOM manipulation
- **Bootstrap 5**: CSS framework for responsive layouts

## Project Structure

```
superb_admin/
├── .env                    # Environment variables
├── package.json            # Project dependencies and scripts
├── README.md               # Project documentation
├── ROLE_BASED_ACCESS_CONTROL.md  # Role-based access control documentation
├── SETUP_INSTRUCTIONS.md   # Setup and installation guide
├── server.js               # Main server application
├── authSchema.js           # Mongoose schema for user authentication
├── validation.js           # Validation utilities
├── registerRoutes.js       # Registration API endpoints
├── dashboard.js            # Dashboard client-side logic
├── dashboard.css           # Dashboard styling
├── login.js                # Login client-side logic
├── login.css               # Login styling
├── register.js             # Registration client-side logic
├── register.css            # Registration styling
├── login.html              # Login page
├── index.html              # Registration page
└── superb_admin_dashboard.html  # Main dashboard interface
```

## Installation Instructions

### Prerequisites
- Node.js (v14 or higher) installed on your system
- MongoDB database (local or cloud instance)
- npm (Node Package Manager)

### Step 1: Project Setup
```bash
# Clone or navigate to the project directory
cd c:/Users/User/Desktop/superb_admin

# Install dependencies
npm install
```

### Step 2: Configure Environment Variables
Create a `.env` file in the project root with the following variables:

```env
# MongoDB Connection String
MONGO_URI=mongodb://localhost:27017/superb_admin

# Server Port
PORT=5000

# JWT Secret Key (use a strong, unique value)
JWT_SECRET=your_super_secret_jwt_key_here

# Optional: Database Name (if not included in MONGO_URI)
DB_NAME=superb_admin
```

### Step 3: Create Initial Admin User
Run the admin creation script to set up the initial admin account:

```bash
node create-admin.js
```

This script will create an admin user with the following credentials (by default):
- Email: admin@example.com
- Password: Admin@123

**Note:** You should modify these default credentials in the `create-admin.js` script for production use.

### Step 4: Start the Server
```bash
node server.js
```

The server will start running on `http://localhost:5000` (or the port specified in your .env file).

## Application Pages and Features

### 1. Login Page (`login.html`)
The authentication portal for users to access the dashboard.

**Key Features:**
- Secure login with email and password
- Form validation (email format, required fields)
- Password visibility toggle
- Loading state indicator during login
- Error handling for invalid credentials
- Remember me functionality (persistent login)
- Responsive design for mobile and desktop

**Files:**
- `login.html`: Login page structure
- `login.css`: Styling for the login interface
- `login.js`: Client-side login logic

### 2. Registration Page (`index.html`)
User registration interface for creating new accounts.

**Key Features:**
- User registration form with email, password, and confirmation
- Password strength validation (8+ chars, uppercase, lowercase, numbers)
- Password requirements checklist
- Form validation and error handling
- Loading states during registration
- Auto-redirect to login page upon success
- Responsive design

**Files:**
- `index.html`: Registration page structure
- `register.css`: Styling for the registration interface
- `register.js`: Client-side registration logic
- `validation.js`: Email and password validation utilities

### 3. Admin Dashboard (`superb_admin_dashboard.html`)
Main dashboard interface for authenticated users.

**Key Features:**
- Dashboard overview with statistics
- User management panel
- Data upload functionality
- Responsive layout with sidebar navigation
- Dynamic content rendering
- Logout functionality
- User profile management

**Files:**
- `superb_admin_dashboard.html`: Dashboard structure
- `dashboard.css`: Dashboard styling
- `dashboard.js`: Client-side dashboard logic

## API Endpoints

### Authentication Endpoints

#### POST /api/login
**Description:** Authenticates user with email and password

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "success": true,
  "token": "jwt_token_here"
}
```

#### POST /api/register
**Description:** Registers a new user account

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Registration successful! You can now login."
}
```

#### GET /api/logout
**Description:** Logs out the currently authenticated user

### User Management Endpoints

#### GET /api/users
**Description:** Retrieves all registered users

**Response:**
```json
{
  "success": true,
  "users": [
    {
      "_id": "user_id",
      "email": "user@example.com",
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ]
}
```

#### DELETE /api/users/:id
**Description:** Deletes a user by ID

#### PUT /api/users/:id
**Description:** Updates user information

### Data Upload Endpoint

#### POST /api/upload
**Description:** Handles file uploads

**Request:** Form data with file field

**Response:**
```json
{
  "success": true,
  "filename": "uploaded_file.csv",
  "path": "/uploads/filename.csv"
}
```

## Authentication and Security

### JWT Authentication
The application uses JWT (JSON Web Tokens) for authentication:

- Tokens are generated upon successful login
- Tokens are stored in localStorage for persistent sessions
- Each protected API endpoint requires a valid token
- Token verification middleware (`verifyToken`) checks for valid tokens

### Password Security
- Passwords are hashed using bcrypt with 10 salt rounds
- Never stored in plain text in the database
- Password strength validation ensures minimum security requirements
- Password reset functionality available (future feature)

### Role-Based Access Control
The application implements role-based access control with two main roles:
- **Admin**: Full access to all features and user management
- **User**: Limited access to dashboard features

For more detailed information, see [ROLE_BASED_ACCESS_CONTROL.md](ROLE_BASED_ACCESS_CONTROL.md).

## Usage Instructions

### 1. Accessing the Dashboard
1. Open your browser and navigate to `http://localhost:5000`
2. You will be redirected to the login page
3. Enter your credentials to log in
4. Upon successful authentication, you'll be taken to the dashboard

### 2. User Management
- From the dashboard, navigate to the Users section
- View, edit, or delete user accounts
- Create new admin users if needed

### 3. Data Upload
- Access the data upload functionality from the dashboard
- Select files to upload (supported formats: CSV, Excel, JSON)
- Uploaded files are processed and stored securely
- View upload history and manage uploaded files

### 4. Logout
- Click the logout button in the dashboard
- Your session will be terminated
- You will be redirected to the login page

## Configuration

### Database Configuration
The application uses MongoDB as its database. The connection string is configured in the `.env` file:

```env
MONGO_URI=mongodb://localhost:27017/superb_admin
```

For production environments, use a cloud MongoDB service like MongoDB Atlas.

### Server Configuration
The server runs on the port specified in the `.env` file. The default port is 5000.

### JWT Configuration
The JWT secret key is used to sign and verify tokens. This should be a long, random string.

## Error Handling

### Common Issues and Solutions

1. **Server won't start**
   - Check if all dependencies are installed (`npm install`)
   - Verify the `.env` file has all required variables
   - Ensure MongoDB is running locally or the connection string is correct

2. **Cannot connect to database**
   - Check MongoDB connection string in `.env`
   - Verify MongoDB server is running
   - Check firewall and network settings

3. **Invalid credentials error**
   - Verify email and password are correct
   - Check if the user account exists in the database
   - Reset password if necessary

4. **Upload fails**
   - Check file size limitations (default: 5MB)
   - Ensure you're uploading supported file formats
   - Check server and client-side error messages

## Development

### Running in Development Mode
The application currently runs in production mode by default. For development, you can use nodemon:

```bash
npm install -g nodemon
nodemon server.js
```

### Debugging
- Use Chrome DevTools for client-side debugging
- Node.js debugger for server-side debugging
- Console logs are available for debugging purposes

### Testing
- Test endpoints using tools like Postman or curl
- Frontend testing with browser DevTools
- Database testing using MongoDB Compass

## Production Deployment

### Environment Variables
For production, ensure you:
- Use secure, unique values for all environment variables
- Store sensitive information in secure locations
- Rotate JWT secret keys periodically

### Security Considerations
- Enable HTTPS
- Implement rate limiting
- Add CORS configuration
- Use secure cookie settings
- Regularly update dependencies
- Implement proper logging

### Performance Optimizations
- Enable compression
- Implement caching
- Optimize database queries
- Use CDNs for static assets
- Monitor server performance

## Future Enhancements

### Planned Features
- Password reset functionality
- User profile management
- Two-factor authentication
- Advanced user filtering and sorting
- Data export capabilities
- Activity logging
- Email notifications
- Dark mode support
- Advanced analytics and reporting

### Improvements
- Enhanced error handling and validation
- More detailed documentation
- Unit and integration testing
- Performance optimizations
- Accessibility improvements

## Contributing

### Development Guidelines
- Follow the existing coding style
- Write clear comments for complex code
- Test changes thoroughly
- Create detailed commit messages
- Submit pull requests with descriptions

### Issue Reporting
- Report bugs with reproduction steps
- Suggest features with use cases
- Provide feedback on existing functionality

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact



*Last updated: February 2026*
#   s u p r b - a d m i n - t e c h n o t e  
 