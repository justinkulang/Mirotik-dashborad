"""Mikrotik Hotspot User Management Backend - Improved Version
Integrates with Mikrotik RouterOS API for user management with improved connection handling."""
from flask import Flask, render_template, request, jsonify, send_from_directory, g
from flask_cors import CORS
import librouteros
from librouteros.exceptions import TrapError
from datetime import datetime, timedelta
import hashlib
import binascii
import socket
import json
import os
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigLoader:
    """Handles loading and managing application configuration."""
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from config.json or create default if not exists."""
        default_config = {
            "mikrotik": {
                "host": "192.168.1.62",
                "port": 8728,
                "username": "admin",
                "password": "",
                "use_ssl": False
            },
            "server": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": True
            }
        }

        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                loaded_config = json.load(f)
                # Merge with default to ensure new keys are present
                default_config.update(loaded_config) 
                return default_config
        else:
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config

    def get_config(self):
        return self.config

    def update_config(self, new_mikrotik_config: dict):
        self.config['mikrotik'].update(new_mikrotik_config)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

# Initialize ConfigLoader
config_loader = ConfigLoader()
app_config = config_loader.get_config()


def get_mikrotik_api():
    """
    Establishes and returns a single Mikrotik API connection per request.
    Stores the connection in Flask's `g` object.
    """
    if 'mikrotik_api' not in g:
        mikrotik_config = app_config['mikrotik']
        host = mikrotik_config['host']
        port = mikrotik_config['port']
        username = mikrotik_config['username']
        password = mikrotik_config['password']
        use_ssl = mikrotik_config.get('use_ssl', False)

        logger.info(f"Attempting to establish new Mikrotik connection for request: Host={host}:{port}, User={username}, SSL={use_ssl}")
        try:
            g.mikrotik_connection = librouteros.connect(
                host=host,
                username=username,
                password=password,
                port=port,
                ssl=use_ssl
            )
            g.mikrotik_api = g.mikrotik_connection # The connection object IS the API
            logger.info("Mikrotik connection established successfully.")
        except TrapError as e:
            # Authentication or permission error from Mikrotik
            logger.error(f"Mikrotik API TrapError (auth/permission): {str(e)}")
            raise ConnectionError(f"Authentication or Permission Error: {str(e)}")
        except socket.error as e:
            # Network-related error (e.g., host unreachable, connection refused)
            logger.error(f"Network socket error connecting to Mikrotik: {str(e)}")
            raise ConnectionError(f"Network Error: Router unreachable or connection refused. ({str(e)})")
        except Exception as e:
            logger.error(f"An unexpected error occurred during Mikrotik connection: {str(e)}")
            raise ConnectionError(f"Unexpected Connection Error: {str(e)}")
    return g.mikrotik_api

@app.teardown_appcontext
def teardown_connection(exception):
    """
    Ensures the Mikrotik connection is closed after each request,
    even if an exception occurs.
    """
    mikrotik_connection = g.pop('mikrotik_connection', None)
    if mikrotik_connection:
        try:
            mikrotik_connection.close()
            logger.info("Mikrotik connection closed.")
        except Exception as e:
            logger.error(f"Error closing Mikrotik connection during teardown: {str(e)}")


# Renamed MikrotikAPI to RouterOSService to better reflect its role
class RouterOSService:
    def __init__(self):
        pass # Connection is managed globally via get_mikrotik_api

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to Mikrotik router."""
        try:
            api = get_mikrotik_api()
            identity_records = list(api.path('system', 'identity').select('name'))
            
            router_name = 'Mikrotik Router'
            if identity_records:
                router_name = identity_records[0].get('name', 'Mikrotik Router')

            return True, f"Connected successfully to {router_name}"
        except ConnectionError as e:
            logger.error(f"Connection test failed: {e}")
            return False, f"Connection failed: {e}"
        except Exception as e:
            logger.error(f"Unexpected error during connection test: {str(e)}")
            return False, f"Unexpected error during connection test: {str(e)}"

    def get_hotspot_users(self) -> list:
        """Get all hotspot users."""
        try:
            api = get_mikrotik_api()
            users = list(api.path('ip', 'hotspot', 'user').select(
                'name', 'profile', 'disabled', 'limit-uptime', 'limit-bytes-total',
                'bytes-in', 'bytes-out', 'comment'
            ))
            return users
        except ConnectionError as e:
            logger.error(f"Error getting users (connection issue): {e}")
            return [] # Return empty list on connection failure
        except Exception as e:
            logger.error(f"Error getting users: {str(e)}")
            return []

    def create_hotspot_user(self, username: str, password: str, profile: str = "default", limit_uptime: str = None, limit_bytes_total: int = None) -> tuple[bool, str]:
        """Create new hotspot user."""
        try:
            api = get_mikrotik_api()
            user_data = {
                'name': username,
                'password': password,
                'profile': profile
            }
            logger.info(f"Attempting to create user '{username}' with profile '{profile}'")

            if limit_uptime:
                user_data['limit-uptime'] = limit_uptime
            if limit_bytes_total:
                user_data['limit-bytes-total'] = str(limit_bytes_total)

            api.path('ip', 'hotspot', 'user').add(**user_data)
            return True, "User created successfully"
        except ConnectionError as e:
            logger.error(f"Error creating user (connection issue): {e}")
            return False, f"Connection Error: {e}"
        except TrapError as e:
            logger.error(f"Mikrotik API TrapError creating user '{username}': {str(e)}")
            return False, f"Mikrotik Error: {str(e)}"
        except Exception as e:
            logger.error(f"An unexpected error occurred creating user '{username}': {str(e)}")
            return False, str(e)

    def delete_hotspot_user(self, username: str) -> tuple[bool, str]:
        """Delete hotspot user."""
        try:
            api = get_mikrotik_api()
            users = list(api.path('ip', 'hotspot', 'user').select('name', '.id'))
            user_id = None
            for user in users:
                if user['name'] == username:
                    user_id = user['.id']
                    break
            if user_id:
                api.path('ip', 'hotspot', 'user').remove(user_id)
                return True, "User deleted successfully"
            else:
                return False, "User not found"
        except ConnectionError as e:
            logger.error(f"Error deleting user (connection issue): {e}")
            return False, f"Connection Error: {e}"
        except TrapError as e:
            logger.error(f"Mikrotik API TrapError deleting user '{username}': {str(e)}")
            return False, f"Mikrotik Error: {str(e)}"
        except Exception as e:
            logger.error(f"Error deleting user: {str(e)}")
            return False, str(e)

    def get_active_sessions(self) -> list:
        """Get active hotspot sessions."""
        try:
            api = get_mikrotik_api()
            sessions = list(api.path('ip', 'hotspot', 'active').select(
                'user', 'address', 'mac-address', 'uptime', 'bytes-in', 'bytes-out',
                'session-time-left', 'idle-time'
            ))
            return sessions
        except ConnectionError as e:
            logger.error(f"Error getting active sessions (connection issue): {e}")
            return []
        except Exception as e:
            logger.error(f"Error getting active sessions: {str(e)}")
            return []

    def disconnect_user(self, username: str) -> tuple[bool, str]:
        """Disconnect active user session."""
        try:
            api = get_mikrotik_api()
            sessions = list(api.path('ip', 'hotspot', 'active').select('user', '.id'))
            session_id = None
            for session in sessions:
                if session.get('user') == username:
                    session_id = session['.id']
                    break
            if session_id:
                api.path('ip', 'hotspot', 'active').remove(session_id)
                return True, "User disconnected successfully"
            else:
                return False, "User session not found"
        except ConnectionError as e:
            logger.error(f"Error disconnecting user (connection issue): {e}")
            return False, f"Connection Error: {e}"
        except TrapError as e:
            logger.error(f"Mikrotik API TrapError disconnecting user '{username}': {str(e)}")
            return False, f"Mikrotik Error: {str(e)}"
        except Exception as e:
            logger.error(f"Error disconnecting user: {str(e)}")
            return False, str(e)

    def get_user_profiles(self) -> list:
        """Get hotspot user profiles."""
        try:
            api = get_mikrotik_api()
            profiles = list(api.path('ip', 'hotspot', 'user', 'profile').select(
                'name', 'rate-limit', 'session-timeout', 'shared-users', 
                'mac-cookie-timeout', 'keepalive-timeout'
            ))
            return profiles
        except ConnectionError as e:
            logger.error(f"Error getting profiles (connection issue): {e}")
            return []
        except Exception as e:
            logger.error(f"Error getting profiles: {str(e)}")
            return []

# Initialize RouterOSService (no direct connection here anymore)
router_os_service = RouterOSService()

@app.route('/')
def index():
    """Serve the main dashboard."""
    return send_from_directory('.', 'mikrotik_userman_dashboard.html')

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test Mikrotik connection."""
    success, message = router_os_service.test_connection()
    return jsonify({'success': success, 'message': message})

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all hotspot users."""
    users = router_os_service.get_hotspot_users()
    formatted_users = []
    for user in users:
        formatted_users.append({
            'username': user.get('name', ''),
            'profile': user.get('profile', 'default'),
            'disabled': user.get('disabled', 'false') == 'true',
            'limit_uptime': user.get('limit-uptime', ''),
            'limit_bytes_total': user.get('limit-bytes-total', ''),
            'bytes_in': user.get('bytes-in', '0'),
            'bytes_out': user.get('bytes-out', '0')
        })
    return jsonify({'users': formatted_users})

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create new hotspot user."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    profile = data.get('profile', 'default')

    time_limit = data.get('time_limit')
    data_limit = data.get('data_limit')

    limit_uptime = None
    if time_limit:
        limit_uptime = f"{int(time_limit) * 3600}s"
    limit_bytes = None
    if data_limit:
        limit_bytes = int(data_limit) * 1024 * 1024  # MB to bytes

    success, message = router_os_service.create_hotspot_user(
        username, password, profile, limit_uptime, limit_bytes
    )

    return jsonify({'success': success, 'message': message})

@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username: str):
    """Delete hotspot user."""
    success, message = router_os_service.delete_hotspot_user(username)
    return jsonify({'success': success, 'message': message})

@app.route('/api/active-sessions', methods=['GET'])
def get_active_sessions_route(): # Renamed to avoid conflict with method name
    """Get active hotspot sessions."""
    sessions = router_os_service.get_active_sessions()
    formatted_sessions = []
    for session in sessions:
        formatted_sessions.append({
            'username': session.get('user', ''),
            'ip': session.get('address', ''),
            'mac': session.get('mac-address', ''),
            'uptime': session.get('uptime', ''),
            'bytes_in': session.get('bytes-in', '0'),
            'bytes_out': session.get('bytes-out', '0'),
            'session_time_left': session.get('session-time-left', ''),
            'idle_time': session.get('idle-time', '')
        })
    return jsonify({'sessions': formatted_sessions})

@app.route('/api/disconnect-user/<username>', methods=['POST'])
def disconnect_user_session(username: str):
    """Disconnect user session."""
    success, message = router_os_service.disconnect_user(username)
    return jsonify({'success': success, 'message': message})

@app.route('/api/profiles', methods=['GET'])
def get_profiles_route(): # Renamed to avoid conflict with method name
    """Get user profiles."""
    profiles = router_os_service.get_user_profiles()
    formatted_profiles = []
    for profile in profiles:
        formatted_profiles.append({
            'name': profile.get('name', ''),
            'rate_limit': profile.get('rate-limit', ''),
            'session_timeout': profile.get('session-timeout', ''),
            'shared_users': profile.get('shared-users', '1'),
            'mac_cookie_timeout': profile.get('mac-cookie-timeout', ''),
            'keepalive_timeout': profile.get('keepalive-timeout', '')
        })
    return jsonify({'profiles': formatted_profiles})

@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics."""
    # These calls now reuse the same connection for the duration of this request
    users = router_os_service.get_hotspot_users()
    sessions = router_os_service.get_active_sessions()

    total_users = len(users)
    active_sessions = len(sessions)

    total_bytes_in = sum(int(session.get('bytes-in', 0)) for session in sessions)
    total_bytes_out = sum(int(session.get('bytes-out', 0)) for session in sessions)
    total_data = (total_bytes_in + total_bytes_out) / (1024 * 1024 * 1024)

    return jsonify({
        'total_users': total_users,
        'active_sessions': active_sessions,
        'data_used_today': f"{total_data:.1f}GB",
        'revenue_today': "$127"
    })

@app.route('/api/update-config', methods=['POST'])
def update_config_route(): # Renamed to avoid conflict with class method name
    """Update Mikrotik connection configuration."""
    data = request.json
    config_loader.update_config(data) # Use the config_loader instance
    return jsonify({'success': True, 'message': 'Configuration updated successfully'})

if __name__ == '__main__':
    print("🚀 Starting Mikrotik Hotspot Management Server...")
    print(f"📊 Dashboard will be available at: http://localhost:{app_config['server']['port']}")
    print("⚙️  Make sure your Mikrotik router API is enabled!")

    app.run(
        host=app_config['server']['host'],
        port=app_config['server']['port'],
        debug=app_config['server']['debug']
    )