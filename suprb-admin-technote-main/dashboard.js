/**
 * Dashboard Logic with Role-Based Access Control
 * Handles user management operations based on user roles
 */

const API_BASE_URL = 'process.env.BACKEND_API';
let currentUserRole = '';

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    loadUsers();
    setupEventListeners();
});

function checkAuth() {
    const token = localStorage.getItem('authToken');
    const userRole = localStorage.getItem('userRole');
    const userEmail = localStorage.getItem('userEmail');

    if (!token || !userRole) {
        window.location.href = 'login.html';
        return;
    }

    // Only allow super admin and admin to access dashboard
    if (userRole !== 'superadmin' && userRole !== 'admin') {
        alert('Access denied. Admin privileges required.');
        logout();
        return;
    }

    currentUserRole = userRole;

    // Display user email and role
    const roleDisplay = userRole === 'superadmin' ? 'Super Admin' : 'Admin';
    document.getElementById('userEmail').innerHTML = `<i class="fa-solid fa-user"></i> ${userEmail} (${roleDisplay})`;

    // Adjust UI based on role
    adjustUIForRole();
}

function adjustUIForRole() {
    const roleSelectionGroup = document.getElementById('roleSelectionGroup');
    const newUserRole = document.getElementById('newUserRole');

    if (currentUserRole === 'admin') {
        // Admin can only create regular users
        if (roleSelectionGroup) {
            roleSelectionGroup.style.display = 'none';
        }
    } else if (currentUserRole === 'superadmin') {
        // Super admin can create any role
        if (roleSelectionGroup) {
            roleSelectionGroup.style.display = 'block';
        }
    }
}

function setupEventListeners() {
    // Logout button
    document.getElementById('logoutBtn').addEventListener('click', logout);

    // Add user button
    document.getElementById('addUserBtn').addEventListener('click', openAddUserModal);

    // Add user form
    document.getElementById('addUserForm').addEventListener('submit', handleAddUser);

    // Change password form
    document.getElementById('changePasswordForm').addEventListener('submit', handleChangePassword);
}

function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userRole');
    window.location.href = 'login.html';
}

// Load all users
async function loadUsers() {
    const token = localStorage.getItem('authToken');
    const tbody = document.getElementById('usersTableBody');

    try {
        const response = await fetch(`${API_BASE_URL}/api/users`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (data.success) {
            displayUsers(data.users);
        } else {
            tbody.innerHTML = `<tr><td colspan="4" class="no-users">${data.message}</td></tr>`;
        }

    } catch (error) {
        console.error('Load users error:', error);
        tbody.innerHTML = `<tr><td colspan="4" class="no-users">Error loading users. Please check if the server is running.</td></tr>`;
    }
}

function displayUsers(users) {
    const tbody = document.getElementById('usersTableBody');

    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="no-users">No users found</td></tr>`;
        return;
    }

    tbody.innerHTML = users.map(user => {
        const canModify = canModifyUser(user.role);
        const roleClass = user.role === 'superadmin' ? 'super-admin' : (user.role === 'admin' ? 'admin' : 'user');
        const roleDisplay = user.role === 'superadmin' ? 'Super Admin' : (user.role === 'admin' ? 'Admin' : 'User');

        // Check if this is the original super admin
        const isOriginalSuperAdmin = user.email === 'sup_admin_enter@gmail.com';

        return `
        <tr>
            <td>${user.email}</td>
            <td>
                <span class="role-badge ${roleClass}">
                    ${roleDisplay}
                </span>
            </td>
            <td>${new Date(user.createdAt).toLocaleString()}</td>
            <td>
                <div class="action-buttons">
                    ${canModify ? `
                        ${currentUserRole === 'superadmin' && !isOriginalSuperAdmin ? `
                            <button class="btn btn-info btn-sm" onclick="openChangeRoleModal('${user._id}', '${user.email}', '${user.role}')">
                                <i class="fa-solid fa-user-shield"></i> Change Role
                            </button>
                        ` : ''}
                        <button class="btn btn-warning btn-sm" onclick="openChangePasswordModal('${user._id}', '${user.email}')">
                            <i class="fa-solid fa-key"></i> Change Password
                        </button>
                        ${user.role !== 'superadmin' ? `
                            <button class="btn btn-danger btn-sm" onclick="openDeleteModal('${user._id}', '${user.email}')">
                                <i class="fa-solid fa-trash"></i> Delete
                            </button>
                        ` : ''}
                    ` : '<span class="text-muted">No actions available</span>'}
                </div>
            </td>
        </tr>
    `;
    }).join('');
}

function canModifyUser(targetRole) {
    if (currentUserRole === 'superadmin') {
        return true; // Super admin can modify anyone
    } else if (currentUserRole === 'admin') {
        return targetRole === 'user'; // Admin can only modify regular users
    }
    return false;
}

// Add User Modal
function openAddUserModal() {
    document.getElementById('addUserModal').classList.add('active');
    document.getElementById('addUserForm').reset();
    adjustUIForRole();
}

function closeAddUserModal() {
    document.getElementById('addUserModal').classList.remove('active');
}

async function handleAddUser(e) {
    e.preventDefault();

    const email = document.getElementById('newUserEmail').value.trim();
    const password = document.getElementById('newUserPassword').value;
    let role = 'user'; // Default role

    // Only super admin can select role
    if (currentUserRole === 'superadmin') {
        role = document.getElementById('newUserRole').value;
    }

    const token = localStorage.getItem('authToken');

    try {
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating...';
        submitBtn.disabled = true;

        const response = await fetch(`${API_BASE_URL}/api/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ email, password, role })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('User created successfully!', 'success');
            closeAddUserModal();
            loadUsers();
        } else {
            showMessage(data.message || 'Failed to create user', 'error');
        }

        submitBtn.innerHTML = originalBtnText;
        submitBtn.disabled = false;

    } catch (error) {
        console.error('Add user error:', error);
        showMessage('Network error. Please try again.', 'error');

        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.innerHTML = '<i class="fa-solid fa-check"></i> Create User';
        submitBtn.disabled = false;
    }
}

// Change Password Modal
function openChangePasswordModal(userId, email) {
    document.getElementById('changePasswordModal').classList.add('active');
    document.getElementById('changePasswordUserId').value = userId;
    document.getElementById('changePasswordEmail').value = email;
    document.getElementById('newPassword').value = '';
}

function closeChangePasswordModal() {
    document.getElementById('changePasswordModal').classList.remove('active');
}

async function handleChangePassword(e) {
    e.preventDefault();

    const userId = document.getElementById('changePasswordUserId').value;
    const newPassword = document.getElementById('newPassword').value;
    const token = localStorage.getItem('authToken');

    try {
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
        submitBtn.disabled = true;

        const response = await fetch(`${API_BASE_URL}/api/users/${userId}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ newPassword })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('Password updated successfully!', 'success');
            closeChangePasswordModal();
        } else {
            showMessage(data.message || 'Failed to update password', 'error');
        }

        submitBtn.innerHTML = originalBtnText;
        submitBtn.disabled = false;

    } catch (error) {
        console.error('Change password error:', error);
        showMessage('Network error. Please try again.', 'error');

        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.innerHTML = '<i class="fa-solid fa-check"></i> Update Password';
        submitBtn.disabled = false;
    }
}

// Change Role Modal (Super Admin Only)
function openChangeRoleModal(userId, email, currentRole) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('changeRoleModal');
    if (!modal) {
        modal = createChangeRoleModal();
        document.body.appendChild(modal);
    }

    document.getElementById('changeRoleUserId').value = userId;
    document.getElementById('changeRoleEmail').value = email;
    document.getElementById('newRole').value = currentRole;
    modal.classList.add('active');
}

function createChangeRoleModal() {
    const modalHTML = `
        <div id="changeRoleModal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fa-solid fa-user-shield"></i> Change User Role</h3>
                    <button class="close-btn" onclick="closeChangeRoleModal()">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                </div>
                <form id="changeRoleForm">
                    <input type="hidden" id="changeRoleUserId" />
                    <div class="form-group">
                        <label for="changeRoleEmail">
                            <i class="fa-solid fa-envelope"></i> User Email
                        </label>
                        <input type="text" id="changeRoleEmail" readonly />
                    </div>
                    <div class="form-group">
                        <label for="newRole">
                            <i class="fa-solid fa-user-shield"></i> New Role
                        </label>
                        <select id="newRole" required>
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                        <small>Select the new role for this user</small>
                    </div>
                    <div class="modal-actions">
                        <button type="button" class="btn btn-secondary" onclick="closeChangeRoleModal()">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fa-solid fa-check"></i> Update Role
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;

    const div = document.createElement('div');
    div.innerHTML = modalHTML;
    const modal = div.firstElementChild;

    // Add form submit handler
    modal.querySelector('#changeRoleForm').addEventListener('submit', handleChangeRole);

    return modal;
}

function closeChangeRoleModal() {
    const modal = document.getElementById('changeRoleModal');
    if (modal) {
        modal.classList.remove('active');
    }
}

async function handleChangeRole(e) {
    e.preventDefault();

    const userId = document.getElementById('changeRoleUserId').value;
    const newRole = document.getElementById('newRole').value;
    const token = localStorage.getItem('authToken');

    try {
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Updating...';
        submitBtn.disabled = true;

        const response = await fetch(`${API_BASE_URL}/api/users/${userId}/role`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ role: newRole })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('User role updated successfully!', 'success');
            closeChangeRoleModal();
            loadUsers();
        } else {
            showMessage(data.message || 'Failed to update role', 'error');
        }

        submitBtn.innerHTML = originalBtnText;
        submitBtn.disabled = false;

    } catch (error) {
        console.error('Change role error:', error);
        showMessage('Network error. Please try again.', 'error');

        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.innerHTML = '<i class="fa-solid fa-check"></i> Update Role';
        submitBtn.disabled = false;
    }
}

// Delete User Modal
function openDeleteModal(userId, email) {
    document.getElementById('deleteModal').classList.add('active');
    document.getElementById('deleteUserId').value = userId;
    document.getElementById('deleteUserEmail').textContent = email;
}

function closeDeleteModal() {
    document.getElementById('deleteModal').classList.remove('active');
}

async function confirmDelete() {
    const userId = document.getElementById('deleteUserId').value;
    const token = localStorage.getItem('authToken');

    try {
        const response = await fetch(`${API_BASE_URL}/api/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (data.success) {
            showMessage('User deleted successfully!', 'success');
            closeDeleteModal();
            loadUsers();
        } else {
            showMessage(data.message || 'Failed to delete user', 'error');
        }

    } catch (error) {
        console.error('Delete user error:', error);
        showMessage('Network error. Please try again.', 'error');
    }
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;

    // Auto-hide after 5 seconds
    setTimeout(() => {
        messageDiv.className = 'message';
    }, 5000);
}

// Close modals when clicking outside
window.onclick = function (event) {
    const addUserModal = document.getElementById('addUserModal');
    const changePasswordModal = document.getElementById('changePasswordModal');
    const deleteModal = document.getElementById('deleteModal');
    const changeRoleModal = document.getElementById('changeRoleModal');

    if (event.target === addUserModal) {
        closeAddUserModal();
    }
    if (event.target === changePasswordModal) {
        closeChangePasswordModal();
    }
    if (event.target === deleteModal) {
        closeDeleteModal();
    }
    if (changeRoleModal && event.target === changeRoleModal) {
        closeChangeRoleModal();
    }
}
