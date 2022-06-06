<script lang="ts">
import { api, Target, UserSnapshot } from 'admin/lib/api'
import { getSSHUsername } from 'admin/lib/ssh'
import { Alert, FormGroup, Modal, ModalBody, ModalHeader } from 'sveltestrap'

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

$: sshUsername = getSSHUsername(selectedUser, selectedTarget)

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
        <a class="list-group-item list-group-item-action" on:click={() => selectedTarget = target}>
            <strong class="me-auto">
                {target.name}
            </strong>
            <small class="text-muted ms-auto">
                {#if target.ssh}
                    SSH
                {/if}
                {#if target.webAdmin}
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
            {#if selectedTarget?.ssh}
                SSH target
            {/if}
            {#if selectedTarget?.webAdmin}
                This web admin interface
            {/if}
        </div>
    </ModalHeader>
    <ModalBody>
        {#if selectedTarget?.ssh}
            <h3>Connection instructions</h3>
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

            <FormGroup floating label="SSH username">
                <input type="text" class="form-control" readonly value={sshUsername} />
            </FormGroup>

            <FormGroup floating label="Example command">
                <input type="text" class="form-control" readonly value={'ssh ' + sshUsername + '@warpgate-host -p warpgate-port'} />
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
