<script lang="ts">
import { api, Target, UserSnapshot } from 'admin/lib/api'
import { makeExampleSSHCommand, makeSSHUsername } from 'common/ssh'
import { Alert, FormGroup, Modal, ModalBody, ModalHeader } from 'sveltestrap'
import { serverInfo } from 'gateway/lib/store'
import CopyButton from 'common/CopyButton.svelte'
import { makeTargetURL } from 'common/http'

let error: Error|undefined
let targets: Target[]|undefined
let selectedTarget: Target|undefined
let users: UserSnapshot[]|undefined
let selectedUser: UserSnapshot|undefined
let sshUsername = ''

async function load () {
    targets = await api.getTargets()
    users = await api.getUsers()
    selectedUser = users[0]
}

load().catch(e => {
    error = e
})

$: sshUsername = makeSSHUsername(selectedTarget?.name, selectedUser?.username)
$: exampleCommand = makeExampleSSHCommand(selectedTarget?.name, selectedUser?.username, $serverInfo)
$: targetURL = selectedTarget ? makeTargetURL(selectedTarget.name) : ''

</script>

{#if error}
<Alert color="danger">{error}</Alert>
{/if}

{#if targets }
<div class="page-summary-bar">
    <h1>Targets</h1>
</div>
<Alert color="info" fade={false}>Add or remove targets in the config file.</Alert>
<div class="list-group list-group-flush">
    {#each targets as target}
        <!-- svelte-ignore a11y-missing-attribute -->
        <a class="list-group-item list-group-item-action" on:click={() => {
            if (target.options.kind !== 'TargetWebAdminOptions') {
                selectedTarget = target
            }
        }}>
            <strong class="me-auto">
                {target.name}
            </strong>
            <small class="text-muted ms-auto">
                {#if target.options.kind === 'TargetSSHOptions'}
                    SSH
                {/if}
                {#if target.options.kind === 'TargetWebAdminOptions'}
                    This web admin interface
                {/if}
            </small>
        </a>
    {/each}
</div>

<Modal isOpen={!!selectedTarget} toggle={() => selectedTarget = undefined}>
    <ModalHeader toggle={() => selectedTarget = undefined}>
        <div>
            {selectedTarget?.name}
        </div>
        <div class="target-type-label">
            {#if selectedTarget?.options.kind === 'TargetSSHOptions'}
                SSH target
            {/if}
            {#if selectedTarget?.options.kind === 'TargetWebAdminOptions'}
                This web admin interface
            {/if}
        </div>
    </ModalHeader>
    <ModalBody>
        <h3>Access instructions</h3>
        {#if selectedTarget?.options.kind === 'TargetSSHOptions'}
            {#if users}
                <FormGroup floating label="Select a user">
                    <select bind:value={selectedUser} class="form-control">
                        {#each users as user}
                            <option value={user}>
                                {user.username}
                            </option>
                        {/each}
                    </select>
                </FormGroup>
            {/if}

            <FormGroup floating label="SSH username" class="d-flex align-items-center">
                <input type="text" class="form-control" readonly value={sshUsername} />
                <CopyButton text={sshUsername} />
            </FormGroup>

            <FormGroup floating label="Example command" class="d-flex align-items-center">
                <input type="text" class="form-control" readonly value={exampleCommand} />
                <CopyButton text={exampleCommand} />
            </FormGroup>
        {/if}

        {#if selectedTarget?.options.kind === 'TargetHTTPOptions'}
            <FormGroup floating label="Access URL" class="d-flex align-items-center">
                <input type="text" class="form-control" readonly value={targetURL} />
                <CopyButton text={targetURL} />
            </FormGroup>
        {/if}
    </ModalBody>
</Modal>
{/if}


<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }

    .target-type-label {
        font-size: 0.8rem;
        opacity: .75;
    }

    :global(.modal-title) {
        line-height: 1.2;
    }
</style>
