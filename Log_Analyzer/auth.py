from werkzeug.security import generate_password_hash, check_password_hash
from models import get_user, create_user

class AuthManager:
    """Handle user authentication and authorization"""
    
    @staticmethod
    def register_user(username, password, role='analyst'):
        """Register a new user"""
        if get_user(username):
            return False, "Username already exists"
        
        hashed_password = generate_password_hash(password)
        success = create_user(username, hashed_password, role)
        
        if success:
            return True, "User registered successfully"
        else:
            return False, "Error registering user"
    
    @staticmethod
    def verify_credentials(username, password):
        """Verify user credentials"""
        user = get_user(username)
        
        if user and check_password_hash(user['password'], password):
            return True, user
        else:
            return False, None
    
    @staticmethod
    def is_admin(user):
        """Check if user is admin"""
        return user and user['role'] == 'admin'
    
    @staticmethod
    def is_analyst(user):
        """Check if user is analyst"""
        return user and user['role'] in ['analyst', 'admin']
