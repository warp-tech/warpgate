#!/usr/bin/env python3
"""
Patch generated OpenAPI Python SDK for CredentialKind enum.
OpenAPI Generator has an upstream bug with 2D arrays of enums where it generates
calls to .to_dict() and .from_dict() assuming inner items are models.
"""
from pathlib import Path

sdk_models = Path(__file__).parent / "api_sdk" / "openapi_client" / "models"
ck_file = sdk_models / "credential_kind.py"

if ck_file.exists():
    content = ck_file.read_text()
    patch_code = """
# Patch for openapi-generator 2D array bug with enums
CredentialKind.to_dict = lambda self: self.value  # type: ignore


def _credential_kind_from_dict(cls, obj):
    if obj is None:
        return None
    if isinstance(obj, cls):
        return obj
    if isinstance(obj, dict):
        return cls(obj.get("value", obj))
    return cls(obj)


CredentialKind.from_dict = classmethod(_credential_kind_from_dict)  # type: ignore
"""
    if "CredentialKind.from_dict" not in content:
        ck_file.write_text(content + patch_code)
        print("Successfully patched credential_kind.py in api_sdk")
    else:
        print("credential_kind.py already patched")
else:
    print(f"File not found: {ck_file}")
