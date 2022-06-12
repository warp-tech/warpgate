<script lang="ts">
import { api, Target, TargetKind } from 'gateway/lib/api'
import { createEventDispatcher } from 'svelte'
import { get } from 'svelte/store'
import { FormGroup, Modal, ModalBody, ModalHeader, Spinner } from 'sveltestrap'
import { authenticatedUsername } from './lib/store'

const dispatch = createEventDispatcher()

let targets: Target[]|undefined
let selectedTarget: Target|undefined
let sshUsername: string

$: sshUsername = `${get(authenticatedUsername)}:${selectedTarget?.name}`

async function init () {
    targets = await api.getTargets()
}

function selectTarget (target: Target) {
    if (target.kind === TargetKind.Http) {
        loadURL(`/?warpgate_target=${target.name}`)
    } else if (target.kind === TargetKind.WebAdmin) {
        loadURL('/@warpgate/admin')
    } else {
        selectedTarget = target
    }
}

function loadURL (url: string) {
    dispatch('navigation')
    location.href = url
}
init()

</script>

<h1>Targets</h1>
{#if targets}
<div class="list-group list-group-flush">
    {#each targets as target}
        <a
            class="list-group-item list-group-item-action"
            href={
                target.kind === TargetKind.Http
                ? `/?warpgate_target=${target.name}`
                : '/@warpgate/admin'
            }
            on:click={e => {
                selectTarget(target)
                e.preventDefault()
            }}
        >{target.name}</a>
    {/each}
</div>
{:else}
    <Spinner />
{/if}

<Modal isOpen={!!selectedTarget} toggle={() => selectedTarget = undefined}>
    <ModalHeader toggle={() => selectedTarget = undefined}>
        <div>
            {selectedTarget?.name}
        </div>
        <div class="target-type-label">
            {#if selectedTarget?.kind === TargetKind.Ssh}
                SSH target
            {/if}
        </div>
    </ModalHeader>
    <ModalBody>
        {#if selectedTarget?.kind === TargetKind.Ssh}
            <h3>Connection instructions</h3>

            <FormGroup floating label="SSH username">
                <input type="text" class="form-control" readonly value={sshUsername} />
            </FormGroup>

            <FormGroup floating label="Example command">
                <input type="text" class="form-control" readonly value={'ssh ' + sshUsername + '@warpgate-host -p warpgate-port'} />
            </FormGroup>
        {/if}
    </ModalBody>
</Modal>
