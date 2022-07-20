<script lang="ts">
import { api, Target, UserSnapshot } from 'admin/lib/api'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { Alert, FormGroup, Modal, ModalBody, ModalHeader } from 'sveltestrap'

let error: Error|undefined
let targets: Target[]|undefined
let selectedTarget: Target|undefined
let users: UserSnapshot[]|undefined
let selectedUser: UserSnapshot|undefined

async function load () {
    targets = await api.getTargets()
    users = await api.getUsers()
    selectedUser = users[0]
}

load().catch(e => {
    error = e
})
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
            if (target.options.kind !== 'WebAdmin') {
                selectedTarget = target
            }
        }}>
            <strong class="me-auto">
                {target.name}
            </strong>
            <small class="text-muted ms-auto">
                {#if target.options.kind === 'Http'}
                    HTTP
                {/if}
                {#if target.options.kind === 'MySql'}
                    MySQL
                {/if}
                {#if target.options.kind === 'Ssh'}
                    SSH
                {/if}
                {#if target.options.kind === 'WebAdmin'}
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
            {#if selectedTarget?.options.kind === 'MySql'}
                MySQL target
            {/if}
            {#if selectedTarget?.options.kind === 'Ssh'}
                SSH target
            {/if}
            {#if selectedTarget?.options.kind === 'WebAdmin'}
                This web admin interface
            {/if}
        </div>
    </ModalHeader>
    <ModalBody>
        <h3>Access instructions</h3>

        {#if selectedTarget?.options.kind === 'Ssh' || selectedTarget?.options.kind === 'MySql'}
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
        {/if}

        <ConnectionInstructions
            targetName={selectedTarget?.name}
            username={selectedUser?.username}
            targetKind={{
                Ssh: TargetKind.Ssh,
                WebAdmin: TargetKind.WebAdmin,
                Http: TargetKind.Http,
                MySql: TargetKind.MySql,
            }[selectedTarget?.options.kind ?? '']}
        />
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
