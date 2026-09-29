#!/usr/bin/env bash
#
# Validate the managed-identity credential on an Azure VM, then remove the VM.
#
# Managed identity resolves through IMDS, a link-local address that only answers
# inside Azure, so this is the one credential mode that cannot be tested from a
# workstation at all. Everything here exists to put the crate somewhere IMDS
# answers, run its tests, and take it away again.
#
# The build happens on the VM. Cross-compiling from macOS to Linux would drag in
# a C toolchain for the transitive native dependencies, which is more moving
# parts than renting a machine for ten minutes.
#
# Usage:   SUBSCRIPTION="<name or id>" tests/azure-managed-identity-e2e.sh
#          KEEP=1 ...    # leave the VM up to poke at
#
set -euo pipefail

SUBSCRIPTION="${SUBSCRIPTION:?set SUBSCRIPTION to the subscription name or id to provision in}"
LOCATION="${LOCATION:-westeurope}"
VM_SIZE="${VM_SIZE:-Standard_D2s_v3}"
SUFFIX="$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8)))')"
RG="wg-azure-mi-${SUFFIX}"
ACCOUNT="wgmi${SUFFIX}"
CONTAINER="recordings"
VM="wg-mi-${SUFFIX}"
KEEP="${KEEP:-0}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() {
    local status=$?
    if [ "$KEEP" = "1" ]; then
        echo
        echo "KEEP=1, leaving these up — delete them yourself when done:"
        echo "  az group delete --name $RG --yes --no-wait"
        return $status
    fi
    echo
    echo "==> Tearing down"
    az group delete --name "$RG" --yes --no-wait 2>/dev/null \
        && echo "    resource group $RG deletion started" \
        || echo "    WARNING: could not delete resource group $RG"
    return $status
}
trap cleanup EXIT INT TERM

echo "==> Subscription"
az account set --subscription "$SUBSCRIPTION"
az account show --query '{name:name, id:id, tenant:tenantId, user:user.name}' -o table
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"

echo
echo "==> Creating resource group $RG in $LOCATION"
az group create --name "$RG" --location "$LOCATION" \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

echo "==> Creating storage account $ACCOUNT"
# Shared-key access off: the point is to prove the identity works, and leaving
# the key path open would let a mistake pass for a success.
az storage account create \
    --name "$ACCOUNT" --resource-group "$RG" --location "$LOCATION" \
    --sku Standard_LRS --kind StorageV2 \
    --allow-blob-public-access false --allow-shared-key-access false \
    --min-tls-version TLS1_2 \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

ACCOUNT_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${ACCOUNT}"

echo "==> Granting the signed-in user data access (to create the container)"
az role assignment create \
    --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
    --assignee-principal-type User \
    --role "Storage Blob Data Contributor" \
    --scope "$ACCOUNT_SCOPE" -o none

echo "==> Creating VM $VM ($VM_SIZE) with a system-assigned identity"
az vm create \
    --name "$VM" --resource-group "$RG" --location "$LOCATION" \
    --image Ubuntu2204 --size "$VM_SIZE" \
    --assign-identity \
    --admin-username azureuser \
    --generate-ssh-keys \
    --os-disk-size-gb 64 \
    --nsg-rule SSH \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true \
    -o none

VM_IP="$(az vm show -d --name "$VM" --resource-group "$RG" --query publicIps -o tsv)"
VM_PRINCIPAL="$(az vm identity show --name "$VM" --resource-group "$RG" --query principalId -o tsv)"
echo "    ip=$VM_IP principal=$VM_PRINCIPAL"

echo "==> Granting the VM's identity data access to the account"
az role assignment create \
    --assignee-object-id "$VM_PRINCIPAL" \
    --assignee-principal-type ServicePrincipal \
    --role "Storage Blob Data Contributor" \
    --scope "$ACCOUNT_SCOPE" -o none

echo "==> Waiting for the role assignments to propagate"
# Entra is eventually consistent; without this the first call fails with a 403
# that reads like a broken credential rather than a race.
sleep 60

echo "==> Creating container $CONTAINER"
az storage container create \
    --name "$CONTAINER" --account-name "$ACCOUNT" --auth-mode login -o none

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15"

echo "==> Waiting for SSH"
for _ in $(seq 1 40); do
    if ssh $SSH_OPTS "azureuser@$VM_IP" true 2>/dev/null; then break; fi
    sleep 5
done
ssh $SSH_OPTS "azureuser@$VM_IP" true

echo "==> Confirming IMDS answers on the VM (the thing that cannot be faked locally)"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "curl -s -H Metadata:true --max-time 10 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' | head -c 120; echo"

echo
echo "==> Installing the build toolchain"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "sudo apt-get update -qq && sudo apt-get install -y -qq build-essential pkg-config libssl-dev clang cmake >/dev/null 2>&1 && echo '    apt ok'"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none >/dev/null 2>&1 && echo '    rustup ok'"

echo "==> Copying the workspace (source only; the build happens there)"
# Excludes are what keep this to seconds: target/ alone is tens of gigabytes.
rsync -az --delete \
    --exclude 'target/' --exclude '.git/' --exclude 'node_modules/' \
    --exclude 'warpgate-web/dist/' --exclude 'tests/api_sdk/' \
    -e "ssh $SSH_OPTS" \
    "$REPO_ROOT/" "azureuser@$VM_IP:~/warpgate/"

echo "==> Building and running the managed-identity tests on the VM"
# Fed over stdin rather than quoted into an argument: the nesting needed to pass
# this as one shell word is where these scripts usually break.
#
# The pinned toolchain installs itself: rustup's cargo shim reads
# rust-toolchain.toml and fetches what it names on first use.
#
# Only this crate and its dependencies are built, not the whole gateway.
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "WARPGATE_AZURE_MI_ACCOUNT='$ACCOUNT' WARPGATE_AZURE_MI_CONTAINER='$CONTAINER' bash -s" <<'REMOTE'
set -euo pipefail
source "$HOME/.cargo/env"
cd ~/warpgate
export CARGO_INCREMENTAL=0
echo "    toolchain: $(cargo --version 2>&1 | head -1)"
cargo test -p warpgate-azure --test managed_identity -- --nocapture --test-threads 1
REMOTE

echo
echo "==> Managed identity verified on an Azure VM"
