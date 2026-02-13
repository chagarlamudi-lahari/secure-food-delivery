# Role-Based Access Control (RBAC)

roles = {
    "user": ["view_profile"],
    "admin": ["view_profile", "view_logs"]
}

def check_access(role, action):
    return action in roles.get(role, [])
