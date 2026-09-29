#!/usr/bin/env bash
#
# Validate the managed-identity credential on an Azure VM, then remove the VM.
#
# Managed identity resolves through IMDS, a link-local address that only answers
# inside Azure, so it is the one credential mode that cannot be tested from a
# workstation at all. Everything here exists to put the crate somewhere IMDS
# answers, run its tests, and take it away again.
#
# The build happens on the VM. Cross-compiling from macOS to Linux would drag in
# a C toolchain for the transitive native dependencies, which is more moving
# parts than renting a machine for ten minutes.
#
# NETWORK POSTURE -- everything below is created fresh and deleted with the
# resource group. Nothing joins an existing network.
#
#   * A dedicated VNet and subnet in this run's own resource group. The VM is
#     never placed on a pre-existing tenant network.
#   * An NSG that DENIES all inbound, with a single exception: TCP 22 from the
#     address this script runs from. Nothing else is reachable from anywhere.
#   * A Standard-SKU public IP, which is closed unless an NSG rule opens it.
#   * The storage account firewall set to DENY by default, then opened to this
#     machine's address and to the VM's subnet through a service endpoint. Its
#     blob endpoint is not reachable from the wider internet.
#   * Shared-key access disabled on the account, so the identity is the only way
#     in and a mistake cannot pass for a success.
#
# Usage:   SUBSCRIPTION="<name or id>" tests/azure-managed-identity-e2e.sh
#          KEEP=1 ...    # leave it up to poke at
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
VNET="${VM}-vnet"
SUBNET="${VM}-subnet"
NSG="${VM}-nsg"
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
    # One delete: every resource above lives in this group, including the
    # network, so nothing can be orphaned by deleting in the wrong order.
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

MY_IP="$(python3 -c "import urllib.request; print(urllib.request.urlopen('https://api.ipify.org', timeout=15).read().decode().strip())")"
echo "    this machine: $MY_IP  (the only address anything will accept)"

echo
echo "==> Creating resource group $RG in $LOCATION"
az group create --name "$RG" --location "$LOCATION" \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

echo "==> Creating a dedicated network (not joining any existing one)"
az network vnet create \
    --resource-group "$RG" --name "$VNET" --location "$LOCATION" \
    --address-prefix 10.42.0.0/24 \
    --subnet-name "$SUBNET" --subnet-prefix 10.42.0.0/24 \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

# Lets the storage account trust this subnet by identity rather than by IP,
# so the blob endpoint needs no public allowance for the VM.
az network vnet subnet update \
    --resource-group "$RG" --vnet-name "$VNET" --name "$SUBNET" \
    --service-endpoints Microsoft.Storage -o none

echo "==> Creating the NSG: deny all inbound, allow SSH from $MY_IP only"
az network nsg create --resource-group "$RG" --name "$NSG" --location "$LOCATION" \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

az network nsg rule create \
    --resource-group "$RG" --nsg-name "$NSG" \
    --name allow-ssh-from-runner --priority 1000 \
    --source-address-prefixes "${MY_IP}/32" \
    --destination-port-ranges 22 \
    --access Allow --protocol Tcp --direction Inbound -o none

# Explicit and last: Azure's own default rules would otherwise permit traffic
# from the whole virtual network, and stating the deny leaves nothing implied.
az network nsg rule create \
    --resource-group "$RG" --nsg-name "$NSG" \
    --name deny-all-inbound --priority 4000 \
    --source-address-prefixes '*' --destination-port-ranges '*' \
    --access Deny --protocol '*' --direction Inbound -o none

echo "==> Creating storage account $ACCOUNT"
az storage account create \
    --name "$ACCOUNT" --resource-group "$RG" --location "$LOCATION" \
    --sku Standard_LRS --kind StorageV2 \
    --allow-blob-public-access false --allow-shared-key-access false \
    --min-tls-version TLS1_2 \
    --tags purpose=warpgate-azure-mi-e2e ephemeral=true -o none

ACCOUNT_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${ACCOUNT}"

echo "==> Closing the storage account to everything but this machine and the subnet"
az storage account network-rule add \
    --account-name "$ACCOUNT" --resource-group "$RG" --ip-address "$MY_IP" -o none
az storage account network-rule add \
    --account-name "$ACCOUNT" --resource-group "$RG" \
    --vnet-name "$VNET" --subnet "$SUBNET" -o none
# Applied after the allowances so the container can still be created below.
az storage account update \
    --name "$ACCOUNT" --resource-group "$RG" --default-action Deny -o none

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
    --vnet-name "$VNET" --subnet "$SUBNET" \
    --nsg "$NSG" \
    --public-ip-sku Standard \
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

echo "==> Confirming the posture before using any of it"
echo "    NSG inbound rules:"
az network nsg rule list --resource-group "$RG" --nsg-name "$NSG" \
    --query "[?direction=='Inbound'].{name:name, priority:priority, access:access, from:sourceAddressPrefix, port:destinationPortRange}" \
    -o table | sed 's/^/      /'
echo "    storage default action: $(az storage account show --name "$ACCOUNT" --resource-group "$RG" --query networkRuleSet.defaultAction -o tsv)"
echo "    shared key access:      $(az storage account show --name "$ACCOUNT" --resource-group "$RG" --query allowSharedKeyAccess -o tsv)"
echo "    public blob access:     $(az storage account show --name "$ACCOUNT" --resource-group "$RG" --query allowBlobPublicAccess -o tsv)"

echo "==> Waiting for the role assignments and network rules to propagate"
# Entra and the storage firewall are both eventually consistent; without this
# the first call fails with a 403 that reads like a broken credential.
sleep 75

echo "==> Creating container $CONTAINER"
az storage container create \
    --name "$CONTAINER" --account-name "$ACCOUNT" --auth-mode login -o none

# IdentitiesOnly pins this to the key az just used. Without it a loaded agent
# offers every key it holds and the server closes the connection for too many
# attempts before reaching the right one, which reads as a refused login.
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o IdentitiesOnly=yes -i $SSH_KEY"

echo "==> Waiting for SSH"
for _ in $(seq 1 40); do
    if ssh $SSH_OPTS "azureuser@$VM_IP" true 2>/dev/null; then break; fi
    sleep 5
done
ssh $SSH_OPTS "azureuser@$VM_IP" true

echo "==> Confirming IMDS answers on the VM (the thing that cannot be faked locally)"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "curl -s -H Metadata:true --max-time 10 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' | head -c 160; echo"

echo
echo "==> Installing the build toolchain"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "sudo apt-get update -qq && sudo apt-get install -y -qq build-essential pkg-config libssl-dev clang cmake rsync >/dev/null 2>&1 && echo '    apt ok'"
ssh $SSH_OPTS "azureuser@$VM_IP" \
    "curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none >/dev/null 2>&1 && echo '    rustup ok'"

echo "==> Copying the workspace (source only; the build happens there)"
# The excludes are what keep this to seconds: target/ alone is tens of gigabytes.
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
