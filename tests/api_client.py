from contextlib import contextmanager

try:
    # in-IDE
    import api_sdk.openapi_client as sdk
except ImportError:
    import openapi_client as sdk

# OpenAPI Generator's Python (pydantic-v2) generator has an upstream bug where 2D
# arrays (list of list) unconditionally call `.to_dict()` and `.from_dict()` on inner
# items without checking if they are Enums or Models.
# CredentialKind is an Enum and does not have `.to_dict()` or `.from_dict()`, so we
# patch it here.
if hasattr(sdk, "CredentialKind"):
    sdk.CredentialKind.to_dict = lambda self: self.value  # type: ignore

    def _from_dict(cls, obj):
        if obj is None:
            return None
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, dict):
            return cls(obj.get("value", obj))
        return cls(obj)

    sdk.CredentialKind.from_dict = classmethod(_from_dict)  # type: ignore



@contextmanager
def admin_client(host, token="token-value"):
    config = sdk.Configuration(
        host=f"{host}/@warpgate/admin/api",
        api_key={
            "TokenSecurityScheme": token,
        },
    )
    config.verify_ssl = False
    with sdk.ApiClient(config) as api_client:
        yield sdk.DefaultApi(api_client)
