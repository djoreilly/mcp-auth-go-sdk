from keycloak import KeycloakAdmin
from keycloak.exceptions import (
    KeycloakGetError,
    KeycloakDeleteError,
)

SERVER_URL = "http://localhost:8090/"
REALM = "mcp-realm"
PROTECTED_RESOURCE = "http://localhost:7777/mcp"
REDIRECT_URL = "http://localhost:3142"
CLIENT_ID = "mcp-test-client"


kc = KeycloakAdmin(
    server_url=SERVER_URL,
    username="admin",
    password="admin",
    realm_name="master",
    pool_maxsize=20,
)

try:
    kc.get_realm(REALM)
    print(f"realm: {REALM} already exists. Deleting...")
    kc.delete_realm(REALM)
except KeycloakDeleteError as e:
    print(f"deleting {REALM}: {e}")
    exit(1)
except KeycloakGetError:
    pass

print(f"creating realm: {REALM} ...")
kc.create_realm({"realm": REALM, "enabled": True})
kc.change_current_realm(REALM)

print("creating user mcp-user")
mcp_user_id = kc.create_user(
    {
        "email": "mcp-user@example.com",
        "username": "mcp-user",
        "enabled": True,
        "firstName": "mcp",
        "lastName": "user",
        "credentials": [{"value": "user123", "type": "password"}],
    }
)

print("creating user mcp-admin")
mcp_admin_id = kc.create_user(
    {
        "email": "mcp-admin@example.com",
        "username": "mcp-admin",
        "enabled": True,
        "firstName": "mcp",
        "lastName": "admin",
        "credentials": [{"value": "admin123", "type": "password"}],
    }
)

print("creating client scope mcp:tools:read")
mcp_read_scope_id = kc.create_client_scope(
    {
        "name": "mcp:tools:read",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": True},
    }
)

print("creating client scope mcp:tools:write")
mcp_write_scope_id = kc.create_client_scope(
    {
        "name": "mcp:tools:write",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": True},
    }
)

# https://www.keycloak.org/securing-apps/mcp-authz-server#_token_audience_binding_and_validation
print("adding mappers for client scopes for audience claim")
kc.add_mapper_to_client_scope(
    mcp_read_scope_id,
    {
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "name": "mapper-for-audience-claim",
        "config": {
            "included.client.audience": "",
            "included.custom.audience": PROTECTED_RESOURCE,
            "id.token.claim": "false",
            "access.token.claim": "true",
            "lightweight.claim": "false",
            "introspection.token.claim": "true",
        },
    },
)

kc.add_mapper_to_client_scope(
    mcp_write_scope_id,
    {
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "name": "mapper-for-audience-claim",
        "config": {
            "included.client.audience": "",
            "included.custom.audience": PROTECTED_RESOURCE,
            "id.token.claim": "false",
            "access.token.claim": "true",
            "lightweight.claim": "false",
            "introspection.token.claim": "true",
        },
    },
)

print(f"creating client: {CLIENT_ID}")
client_id = kc.create_client(
    {
        "clientId": CLIENT_ID,
        "description": "blab",
        "redirectUris": [REDIRECT_URL],
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "clientAuthenticatorType": "client-secret",
        "secret": "secret",
    }
)

print(f"adding client scope mcp:tools:read scopes to {CLIENT_ID}")
kc.add_client_optional_client_scope(
    client_id,
    mcp_read_scope_id,
    payload={"realm": REALM, "client": client_id, "clientScopeId": mcp_read_scope_id},
)

print(f"adding client scope mcp:tools:write scopes to {CLIENT_ID}")
kc.add_client_optional_client_scope(
    client_id,
    mcp_write_scope_id,
    payload={"realm": REALM, "client": client_id, "clientScopeId": mcp_write_scope_id},
)

print("creating client roles: mcp-read and mcp-write")
kc.create_client_role(client_id, {"name": "mcp-read"})
read_role = kc.get_client_role(client_id, "mcp-read")
kc.create_client_role(client_id, {"name": "mcp-write"})
write_role = kc.get_client_role(client_id, "mcp-write")

print("assigning role mcp-read to mcp-user")
kc.assign_client_role(mcp_user_id, client_id, [read_role])

print("assigning roles mcp-read and mcp-write to mcp-admin")
kc.assign_client_role(mcp_admin_id, client_id, [read_role, write_role])

print("add mapping from mcp:tools:read to mcp-test-client mcp-read")
kc.add_client_specific_roles_to_client_scope(mcp_read_scope_id, client_id, [read_role])

print("add mapping from mcp:tools:write to mcp-test-client mcp-write")
kc.add_client_specific_roles_to_client_scope(
    mcp_write_scope_id, client_id, [write_role]
)

print("done")
