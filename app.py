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
import random
import string
import re

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
                '.id', 'name', 'profile', 'disabled', 'limit-uptime', 'limit-bytes-total', # Added .id
                'bytes-in', 'bytes-out', 'comment', 'limit-bytes-in', 'limit-bytes-out'
            ))
            return users
        except ConnectionError as e:
            logger.error(f"Error getting users (connection issue): {e}")
            return [] # Return empty list on connection failure
        except Exception as e:
            logger.error(f"Error getting users: {str(e)}")
            return []

    def create_hotspot_user(self, username: str, password: str, profile: str = "default",
                            limit_uptime: str = None, limit_bytes_total: int = None,
                            comment: str = None, limit_bytes_in: int = None,
                            limit_bytes_out: int = None) -> tuple[bool, str]:
        """Create new hotspot user with extended parameters."""
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
            if limit_bytes_total is not None: # Ensure 0 is also processed
                user_data['limit-bytes-total'] = str(limit_bytes_total)
            if comment is not None:
                user_data['comment'] = comment
            if limit_bytes_in is not None:
                user_data['limit-bytes-in'] = str(limit_bytes_in)
            if limit_bytes_out is not None:
                user_data['limit-bytes-out'] = str(limit_bytes_out)

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

    def edit_hotspot_user(self, username: str, new_data: dict) -> tuple[bool, str]:
        """Edit existing hotspot user."""
        try:
            api = get_mikrotik_api()
            # Find user by name to get .id
            users = list(api.path('ip', 'hotspot', 'user').select('.id', 'name').where(name=username))
            if not users:
                return False, "User not found"
            user_id = users[0]['.id']

            params_to_set = {}
            if 'password' in new_data and new_data['password']: # Ensure password is not empty
                params_to_set['password'] = new_data['password']
            if 'profile' in new_data:
                params_to_set['profile'] = new_data['profile']
            if 'limit_uptime' in new_data: # Assumes already in ROS format or None
                params_to_set['limit-uptime'] = new_data['limit_uptime']
            if 'limit_bytes_total' in new_data: # Assumes already in bytes or None
                params_to_set['limit-bytes-total'] = str(new_data['limit_bytes_total']) if new_data['limit_bytes_total'] is not None else None
            if 'limit_bytes_in' in new_data:
                params_to_set['limit-bytes-in'] = str(new_data['limit_bytes_in']) if new_data['limit_bytes_in'] is not None else None
            if 'limit_bytes_out' in new_data:
                params_to_set['limit-bytes-out'] = str(new_data['limit_bytes_out']) if new_data['limit_bytes_out'] is not None else None
            if 'comment' in new_data:
                params_to_set['comment'] = new_data['comment']
            if 'disabled' in new_data and isinstance(new_data['disabled'], bool):
                params_to_set['disabled'] = 'true' if new_data['disabled'] else 'false'

            # Filter out None values, as Mikrotik API might not like them for some fields
            # Or some fields might require explicit clearing (e.g. by setting to empty string or specific value)
            # For now, we assume sending None is okay for optional fields if they are not to be changed,
            # but if a field is in params_to_set, it means user wants to change it.
            # If a value is None (e.g. user wants to remove limit), how ROS API handles this varies.
            # Typically, to remove a limit, you'd set it to "0" or an empty string depending on the parameter.
            # This implementation assumes that if a key is present with None, it's an attempt to clear it,
            # which might need more specific handling per field (e.g. limit-uptime="0s").
            # For simplicity, we will pass what's given. A value of None in new_data means "don't change".
            # A value of e.g. 0 for a limit means "set to 0".
            # This logic needs to be handled carefully in the route handler before calling this.
            # The current logic here is: if a key is in params_to_set, it's an explicit update.

            final_params_to_set = {k: v for k, v in params_to_set.items() if v is not None}


            if not final_params_to_set:
                return False, "No valid parameters provided for update"

            logger.info(f"Attempting to update user '{username}' (ID: {user_id}) with params: {final_params_to_set}")
            api.path('ip', 'hotspot', 'user').set(**final_params_to_set, **{'.id': user_id})
            return True, "User updated successfully"
        except ConnectionError as e:
            logger.error(f"Error editing user '{username}' (connection issue): {e}")
            return False, f"Connection Error: {e}"
        except TrapError as e:
            logger.error(f"Mikrotik API TrapError editing user '{username}': {str(e)}")
            return False, f"Mikrotik Error: {str(e)}"
        except Exception as e:
            logger.error(f"An unexpected error occurred editing user '{username}': {str(e)}")
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

    def clear_user_counters(self, scope: str, group_name: str = None) -> tuple[bool, str, int]:
        """Clear counters for hotspot users based on scope."""
        try:
            api = get_mikrotik_api()
            hotspot_user_path = api.path('ip', 'hotspot', 'user')

            users_to_target = []
            all_users = list(hotspot_user_path.select('.id', 'name', 'profile'))

            if scope == "all":
                users_to_target = all_users
            elif scope == "group":
                if not group_name:
                    return False, "Group name (profile) is required for group scope", 0
                users_to_target = [user for user in all_users if user.get('profile') == group_name]
            else:
                return False, f"Invalid scope '{scope}'. Supported scopes are 'all', 'group'.", 0

            if not users_to_target:
                return True, "No users found for the given scope to clear counters.", 0

            cleared_count = 0
            errors = []
            for user in users_to_target:
                user_id = user['.id']
                user_name = user.get('name', user_id) # For logging
                try:
                    # Mikrotik's 'reset-counters' command typically takes 'numbers' which can be .id, name, or list index
                    hotspot_user_path.call('reset-counters', {'numbers': user_id})
                    logger.info(f"Successfully cleared counters for user '{user_name}' (ID: {user_id})")
                    cleared_count += 1
                except TrapError as e:
                    logger.error(f"TrapError clearing counters for user '{user_name}' (ID: {user_id}): {str(e)}")
                    errors.append(f"Failed for {user_name}: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error clearing counters for user '{user_name}' (ID: {user_id}): {str(e)}")
                    errors.append(f"Unexpected error for {user_name}: {str(e)}")

            if cleared_count == len(users_to_target):
                return True, f"Counters cleared successfully for {cleared_count} user(s).", cleared_count
            else:
                error_summary = "; ".join(errors)
                return False, f"Cleared counters for {cleared_count}/{len(users_to_target)} users. Errors: {error_summary}", cleared_count

        except ConnectionError as e:
            logger.error(f"ConnectionError during clear_user_counters: {e}")
            return False, f"Connection Error: {str(e)}", 0
        except Exception as e:
            logger.error(f"General error during clear_user_counters: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}", 0

    def delete_users_bulk(self, scope: str, group_name: str = None) -> tuple[bool, str, int]:
        """Delete hotspot users in bulk based on scope."""
        try:
            api = get_mikrotik_api()
            hotspot_user_path = api.path('ip', 'hotspot', 'user')

            users_to_target = []
            all_users = list(hotspot_user_path.select('.id', 'name', 'profile'))

            if scope == "all":
                users_to_target = all_users
            elif scope == "group":
                if not group_name:
                    return False, "Group name (profile) is required for group scope", 0
                users_to_target = [user for user in all_users if user.get('profile') == group_name]
            else:
                return False, f"Invalid scope '{scope}'. Supported scopes are 'all', 'group'.", 0

            if not users_to_target:
                return True, "No users found for the given scope to delete.", 0

            deleted_count = 0
            errors = []
            for user in users_to_target:
                user_id = user['.id']
                user_name = user.get('name', user_id) # For logging
                try:
                    hotspot_user_path.remove(user_id) # '.id' is implicitly used by remove if given as arg
                    logger.info(f"Successfully deleted user '{user_name}' (ID: {user_id})")
                    deleted_count += 1
                except TrapError as e:
                    logger.error(f"TrapError deleting user '{user_name}' (ID: {user_id}): {str(e)}")
                    errors.append(f"Failed for {user_name}: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error deleting user '{user_name}' (ID: {user_id}): {str(e)}")
                    errors.append(f"Unexpected error for {user_name}: {str(e)}")

            if deleted_count == len(users_to_target):
                return True, f"Successfully deleted {deleted_count} user(s).", deleted_count
            else:
                error_summary = "; ".join(errors)
                return False, f"Deleted {deleted_count}/{len(users_to_target)} users. Errors: {error_summary}", deleted_count

        except ConnectionError as e:
            logger.error(f"ConnectionError during delete_users_bulk: {e}")
            return False, f"Connection Error: {str(e)}", 0
        except Exception as e:
            logger.error(f"General error during delete_users_bulk: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}", 0

# Initialize RouterOSService (no direct connection here anymore)
router_os_service = RouterOSService()

# Helper function to convert time limit string to RouterOS format
def convert_time_limit_to_ros_format(time_limit_str: str) -> str:
    """
    Converts a time limit string (e.g., "1h30m", "2h", "45m") to RouterOS uptime format (e.g., "1h30m0s").
    Returns None if the input is empty or invalid.
    """
    if not time_limit_str:
        return None

    hours = 0
    minutes = 0
    seconds = 0 # RouterOS format often includes seconds

    hour_match = re.search(r'(\d+)h', time_limit_str)
    if hour_match:
        hours = int(hour_match.group(1))

    minute_match = re.search(r'(\d+)m', time_limit_str)
    if minute_match:
        minutes = int(minute_match.group(1))

    # If no hours or minutes are found, but the string is not empty, it might be an invalid format
    # For simplicity, we are assuming valid inputs or relying on Mikrotik to reject invalid formats.
    # A more robust parser could be implemented if needed.
    if not hour_match and not minute_match and time_limit_str: # e.g. "abc"
        return None # Or raise an error

    return f"{hours}h{minutes}m{seconds}s"


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
            'bytes_out': user.get('bytes-out', '0'),
            'comment': user.get('comment', ''),
            'limit_bytes_in': user.get('limit-bytes-in', ''),
            'limit_bytes_out': user.get('limit-bytes-out', '')
        })
    return jsonify({'users': formatted_users})

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create new hotspot user."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    profile = data.get('profile', 'default') # Existing
    comment = data.get('comment') # New

    # Existing time_limit and data_limit (total)
    time_limit_str = data.get('time_limit') # Expects string like "1h", "30m" or "2h30m"
    data_limit_total_mb = data.get('data_limit') # Expects MB

    # New data limits for Tx/Rx
    data_limit_tx_mb = data.get('data_limit_tx_mb') # Expects MB
    data_limit_rx_mb = data.get('data_limit_rx_mb') # Expects MB

    limit_uptime_ros = None
    if time_limit_str: # Use existing helper for consistency
        limit_uptime_ros = convert_time_limit_to_ros_format(time_limit_str)
        if not limit_uptime_ros: # If conversion fails (e.g. invalid format)
            logger.warning(f"Invalid time_limit format received: {time_limit_str}. Ignoring.")
            # Potentially return error: return jsonify({'success': False, 'message': 'Invalid time_limit format'}), 400


    limit_bytes_total = int(data_limit_total_mb * 1024 * 1024) if data_limit_total_mb is not None else None
    limit_bytes_in = int(data_limit_tx_mb * 1024 * 1024) if data_limit_tx_mb is not None else None
    limit_bytes_out = int(data_limit_rx_mb * 1024 * 1024) if data_limit_rx_mb is not None else None

    if not username or not password:
         return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    success, message = router_os_service.create_hotspot_user(
        username=username,
        password=password,
        profile=profile,
        limit_uptime=limit_uptime_ros,
        limit_bytes_total=limit_bytes_total,
        comment=comment,
        limit_bytes_in=limit_bytes_in,
        limit_bytes_out=limit_bytes_out
    )

    return jsonify({'success': success, 'message': message})

@app.route('/api/bulk-create-users', methods=['POST'])
def bulk_create_users():
    data = request.json
    logger.info(f"Bulk create request received: {data}")

    number_of_users = data.get('number_of_users')
    profile = data.get('profile')
    time_limit_str = data.get('time_limit') # e.g., "1h30m"
    data_limit_total_mb = data.get('data_limit_total') # in MB
    data_limit_tx_mb = data.get('data_limit_tx') # in MB
    data_limit_rx_mb = data.get('data_limit_rx') # in MB
    comment_prefix = data.get('comment_prefix', '')
    username_length = data.get('username_length', 6)
    password_length = data.get('password_length', 8)

    if not isinstance(number_of_users, int) or number_of_users <= 0:
        return jsonify({'success': False, 'message': 'Number of users must be a positive integer.'}), 400
    if not profile:
        return jsonify({'success': False, 'message': 'Profile is required.'}), 400
    if not isinstance(username_length, int) or username_length <= 0:
        username_length = 6
    if not isinstance(password_length, int) or password_length <= 0:
        password_length = 8

    limit_uptime_ros = None
    if time_limit_str:
        limit_uptime_ros = convert_time_limit_to_ros_format(time_limit_str)
        if limit_uptime_ros is None:
             logger.warning(f"Invalid time_limit format: {time_limit_str}. Proceeding without uptime limit.")
             # Optionally, you could return an error here:
             # return jsonify({'success': False, 'message': f"Invalid time_limit format: {time_limit_str}"}), 400


    limit_bytes_total = int(data_limit_total_mb * 1024 * 1024) if data_limit_total_mb else None
    limit_bytes_in = int(data_limit_tx_mb * 1024 * 1024) if data_limit_tx_mb else None # Upload limit
    limit_bytes_out = int(data_limit_rx_mb * 1024 * 1024) if data_limit_rx_mb else None # Download limit

    successfully_created_count = 0
    failed_users_count = 0
    errors = []
    created_usernames = set() # To ensure uniqueness within this batch

    try:
        api = get_mikrotik_api()
        user_path = api.path('ip', 'hotspot', 'user')

        for i in range(number_of_users):
            # Generate unique username
            while True:
                username = ''.join(random.choices(string.ascii_letters + string.digits, k=username_length))
                if username not in created_usernames: # Highly unlikely to collide often with reasonable length
                    created_usernames.add(username)
                    break

            password = ''.join(random.choices(string.ascii_letters + string.digits, k=password_length))

            user_data = {
                'name': username,
                'password': password,
                'profile': profile,
                'comment': f"{comment_prefix}{username}" if comment_prefix else username # Or use a sequential number
            }

            if limit_uptime_ros:
                user_data['limit-uptime'] = limit_uptime_ros
            if limit_bytes_total:
                user_data['limit-bytes-total'] = str(limit_bytes_total)
            if limit_bytes_in:
                user_data['limit-bytes-in'] = str(limit_bytes_in)
            if limit_bytes_out:
                user_data['limit-bytes-out'] = str(limit_bytes_out)

            try:
                logger.info(f"Attempting to bulk create user: {username} with profile: {profile}")
                user_path.add(**user_data)
                successfully_created_count += 1
            except TrapError as e:
                logger.error(f"TrapError creating user {username} during bulk operation: {str(e)}")
                failed_users_count += 1
                errors.append({'username': username, 'error': str(e)})
            except Exception as e:
                logger.error(f"Unexpected error creating user {username} during bulk operation: {str(e)}")
                failed_users_count += 1
                errors.append({'username': username, 'error': f"Unexpected error: {str(e)}"})
                # Depending on the error, you might want to break the loop or continue
                # For now, we continue to try creating other users.

        return jsonify({
            'success': True,
            'requested_users': number_of_users,
            'successful_users': successfully_created_count,
            'failed_users': failed_users_count,
            'errors': errors
        })

    except ConnectionError as e:
        logger.error(f"ConnectionError during bulk user creation: {str(e)}")
        return jsonify({'success': False, 'message': f"Connection Error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"General error during bulk user creation: {str(e)}")
        return jsonify({'success': False, 'message': f"An unexpected error occurred: {str(e)}"}), 500


@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username: str):
    """Delete hotspot user."""
    success, message = router_os_service.delete_hotspot_user(username)
    return jsonify({'success': success, 'message': message})

@app.route('/api/users/<username>', methods=['PUT'])
def edit_user_route(username: str):
    """Edit existing hotspot user."""
    data = request.json
    logger.info(f"Attempting to edit user '{username}' with data: {data}")

    processed_data = {}

    if 'password' in data and data['password']: # Ensure password is not empty string
        processed_data['password'] = data['password']
    if 'profile' in data:
        processed_data['profile'] = data['profile']
    if 'comment' in data:
        processed_data['comment'] = data['comment']
    if 'disabled' in data and isinstance(data['disabled'], bool):
        processed_data['disabled'] = data['disabled'] # Pass boolean, service method will convert

    # Time limit conversion (e.g., from "1h30m" or "2h")
    if 'time_limit' in data: # Frontend might send "1h30m"
        time_limit_str = data.get('time_limit')
        if time_limit_str is not None: # Could be empty string meaning "remove limit"
            ros_time = convert_time_limit_to_ros_format(time_limit_str)
            if ros_time:
                processed_data['limit_uptime'] = ros_time
            elif time_limit_str == "": # Explicitly clear
                 processed_data['limit_uptime'] = "0s" # Or how Mikrotik expects clearing
            else: # Invalid format
                # Log warning or return error, for now, we log and skip
                logger.warning(f"Invalid time_limit format for edit: {time_limit_str}. Field will not be updated.")
        else: # if time_limit key exists but value is null
            processed_data['limit_uptime'] = None # Let service decide if this means "don't change" or "clear"

    # Data limit conversions (from MB to bytes)
    if 'data_limit_total_mb' in data:
        val = data['data_limit_total_mb']
        processed_data['limit_bytes_total'] = int(val * 1024 * 1024) if val is not None else None
    if 'data_limit_tx_mb' in data: # Upload
        val = data['data_limit_tx_mb']
        processed_data['limit_bytes_in'] = int(val * 1024 * 1024) if val is not None else None
    if 'data_limit_rx_mb' in data: # Download
        val = data['data_limit_rx_mb']
        processed_data['limit_bytes_out'] = int(val * 1024 * 1024) if val is not None else None

    if not processed_data:
        return jsonify({'success': False, 'message': "No valid fields provided for update."}), 400

    success, message = router_os_service.edit_hotspot_user(username, processed_data)
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

@app.route('/api/clear-counters', methods=['POST'])
def clear_counters_route():
    data = request.json
    scope = data.get('scope')
    group_name = data.get('group_name') # Optional, used if scope is 'group'

    if not scope:
        return jsonify({'success': False, 'message': "Scope is required ('all' or 'group')."}), 400

    if scope.lower() == "expired":
        return jsonify({'success': False, 'message': "Scope 'expired' is not supported for counter clearing."}), 400
    if scope.lower() not in ["all", "group"]:
        return jsonify({'success': False, 'message': "Invalid scope. Must be 'all' or 'group'."}), 400
    if scope.lower() == "group" and not group_name:
        return jsonify({'success': False, 'message': "group_name is required when scope is 'group'."}), 400

    success, message, count = router_os_service.clear_user_counters(scope.lower(), group_name)
    return jsonify({'success': success, 'message': message, 'cleared_count': count})

@app.route('/api/bulk-delete-users', methods=['POST'])
def bulk_delete_users_route():
    data = request.json
    scope = data.get('scope')
    group_name = data.get('group_name') # Optional, used if scope is 'group'

    if not scope:
        return jsonify({'success': False, 'message': "Scope is required ('all' or 'group')."}), 400

    if scope.lower() == "expired":
        return jsonify({'success': False, 'message': "Scope 'expired' is not supported for bulk deletion."}), 400
    if scope.lower() not in ["all", "group"]:
        return jsonify({'success': False, 'message': "Invalid scope. Must be 'all' or 'group'."}), 400
    if scope.lower() == "group" and not group_name:
        return jsonify({'success': False, 'message': "group_name is required when scope is 'group'."}), 400

    success, message, count = router_os_service.delete_users_bulk(scope.lower(), group_name)
    return jsonify({'success': success, 'message': message, 'deleted_count': count})

if __name__ == '__main__':
    print("🚀 Starting Mikrotik Hotspot Management Server...")
    print(f"📊 Dashboard will be available at: http://localhost:{app_config['server']['port']}")
    print("⚙️  Make sure your Mikrotik router API is enabled!")

    app.run(
        host=app_config['server']['host'],
        port=app_config['server']['port'],
        debug=app_config['server']['debug']
    )