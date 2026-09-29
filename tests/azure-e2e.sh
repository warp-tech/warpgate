#!/usr/bin/env bash
#
# Provision a throwaway Azure storage account, run the Azure recordings tests
# against it, and remove everything again.
#
# Azurite cannot serve these tests: azure_storage_blob 1.x authenticates with
# Entra ID only and refuses a non-HTTPS endpoint once a credential is present.
# A real account is the only way to exercise the backend, so this script makes
# the smallest possible one and deletes it on the way out.
#
# Everything it creates is named with a single random suffix and lives in one
# resource group, so teardown is one delete and nothing is left behind if the
# tests fail. The trap runs on success, failure and interrupt alike.
#
# Usage:   tests/azure-e2e.sh [pytest args...]
#          KEEP=1 tests/azure-e2e.sh      # leave the resources up for poking at
#
set -euo pipefail

# The subscription to provision in. Required and never defaulted: the account's
# default subscription is whatever was last selected, and throwaway resources
# should not land there by accident.
SUBSCRIPTION="${SUBSCRIPTION:?set SUBSCRIPTION to the subscription name or id to provision in}"
LOCATION="${LOCATION:-westeurope}"
# Generated without a pipe on purpose: `tr </dev/urandom | head -c 8` makes head
# close the pipe first, which hands tr a SIGPIPE that pipefail then treats as a
# failed command, and set -e kills the script before it does anything.
SUFFIX="$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8)))')"
RG="wg-azure-e2e-${SUFFIX}"
# Storage account names are 3-24 chars, lowercase alphanumeric only.
ACCOUNT="wgtest${SUFFIX}"
CONTAINER="recordings"
SP_NAME="wg-azure-e2e-${SUFFIX}"
KEEP="${KEEP:-0}"

SP_APP_ID=""

cleanup() {
    local status=$?
    if [ "$KEEP" = "1" ]; then
        echo
        echo "KEEP=1, leaving these in place — delete them yourself when done:"
        echo "  az group delete --name $RG --yes --no-wait"
        [ -n "$SP_APP_ID" ] && echo "  az ad sp delete --id $SP_APP_ID"
        return $status
    fi
    echo
    echo "==> Tearing down"
    # Best-effort: a failure here must not mask the test's own exit status.
    if [ -n "$SP_APP_ID" ]; then
        az ad sp delete --id "$SP_APP_ID" 2>/dev/null \
            && echo "    service principal deleted" \
            || echo "    WARNING: could not delete service principal $SP_APP_ID"
    fi
    az group delete --name "$RG" --yes --no-wait 2>/dev/null \
        && echo "    resource group $RG deletion started" \
        || echo "    WARNING: could not delete resource group $RG"
    return $status
}
trap cleanup EXIT INT TERM

echo "==> Subscription"
# Pin it for every subsequent call rather than relying on the active default.
az account set --subscription "$SUBSCRIPTION"
az account show --query '{name:name, id:id, tenant:tenantId, user:user.name}' -o table

SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"

echo
echo "==> Creating resource group $RG in $LOCATION"
az group create --name "$RG" --location "$LOCATION" \
    --tags purpose=warpgate-azure-e2e ephemeral=true -o none

echo "==> Creating storage account $ACCOUNT"
# Standard_LRS is the cheapest redundancy, and the account exists for minutes.
# Shared-key access is disabled because the backend cannot use it anyway, which
# keeps the account honest about what is being tested.
az storage account create \
    --name "$ACCOUNT" \
    --resource-group "$RG" \
    --location "$LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --allow-blob-public-access false \
    --allow-shared-key-access false \
    --min-tls-version TLS1_2 \
    --tags purpose=warpgate-azure-e2e ephemeral=true \
    -o none

ACCOUNT_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${ACCOUNT}"

echo "==> Granting the signed-in user data access"
# Creating the container and running the DeveloperTools mode both act as the
# logged-in user, and control-plane ownership does not imply data-plane access.
CURRENT_USER_ID="$(az ad signed-in-user show --query id -o tsv)"
az role assignment create \
    --assignee-object-id "$CURRENT_USER_ID" \
    --assignee-principal-type User \
    --role "Storage Blob Data Contributor" \
    --scope "$ACCOUNT_SCOPE" -o none

echo "==> Creating service principal $SP_NAME"
SP_JSON="$(az ad sp create-for-rbac \
    --name "$SP_NAME" \
    --role "Storage Blob Data Contributor" \
    --scopes "$ACCOUNT_SCOPE" \
    -o json)"
SP_APP_ID="$(echo "$SP_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["appId"])')"
SP_SECRET="$(echo "$SP_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["password"])')"

echo "==> Waiting for the role assignments to propagate"
# Entra role assignments are eventually consistent; without this the first
# request fails with a 403 that looks like a bug in the backend.
sleep 45

echo "==> Creating container $CONTAINER"
az storage container create \
    --name "$CONTAINER" \
    --account-name "$ACCOUNT" \
    --auth-mode login \
    -o none

echo
echo "==> Running the tests"
export WARPGATE_AZURE_TEST_ACCOUNT="$ACCOUNT"
export WARPGATE_AZURE_TEST_CONTAINER="$CONTAINER"
export WARPGATE_AZURE_TEST_TENANT_ID="$TENANT_ID"
export WARPGATE_AZURE_TEST_CLIENT_ID="$SP_APP_ID"
export WARPGATE_AZURE_TEST_CLIENT_SECRET="$SP_SECRET"

cd "$(dirname "$0")"
poetry run pytest -v --timeout 300 test_recordings_azure.py "$@"
