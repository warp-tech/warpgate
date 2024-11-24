from contextlib import contextmanager

try:
    # in-IDE
    import api_sdk.openapi_client as sdk
except ImportError:
    import openapi_client as sdk



@contextmanager
def admin_client(host):
    config = sdk.Configuration(
        host=f"{host}/@warpgate/admin/api",
        api_key={
            "TokenSecurityScheme": "token-value",
        },
    )
    config.verify_ssl = False
    with sdk.ApiClient(config) as api_client:
        yield sdk.DefaultApi(api_client)
