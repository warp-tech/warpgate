<script lang="ts">
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import CopyButton from 'common/CopyButton.svelte'
import { makeExampleSSHCommand, makeSSHUsername } from 'common/ssh';
import { api, Target, TargetKind } from 'gateway/lib/api'
import { createEventDispatcher } from 'svelte'
import Fa from 'svelte-fa'
import { FormGroup, Modal, ModalBody, ModalHeader, Spinner } from 'sveltestrap'
import { serverInfo } from './lib/store'

const dispatch = createEventDispatcher()

let targets: Target[]|undefined
let selectedTarget: Target|undefined
let sshUsername: string

$: sshUsername = makeSSHUsername(selectedTarget?.name, $serverInfo?.username)
$: exampleCommand = makeExampleSSHCommand(selectedTarget?.name, $serverInfo?.username, $serverInfo)

async function init () {
    targets = await api.getTargets()
}

function selectTarget (target: Target) {
    if (target.kind === TargetKind.Http) {
        loadURL(`/?warpgate-target=${target.name}`)
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

{#if targets}
<div class="list-group list-group-flush">
    {#each targets as target}
        <a
            class="list-group-item list-group-item-action target-item"
            href={
                target.kind === TargetKind.Http
                ? `/?warpgate-target=${target.name}`
                : '/@warpgate/admin'
            }
            on:click={e => {
                if (e.metaKey || e.ctrlKey) {
                    return
                }
                selectTarget(target)
                e.preventDefault()
            }}
        >
            <span class="me-auto">{target.name}</span>
            <small class="protocol text-muted ms-auto">
                {#if target.kind === TargetKind.Ssh}
                    SSH
                {/if}
            </small>
            {#if target.kind === TargetKind.Http || target.kind === TargetKind.WebAdmin}
                <Fa icon={faArrowRight} fw />
            {/if}
        </a>
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
    </ModalHeader>
    <ModalBody>
        {#if selectedTarget?.kind === TargetKind.Ssh}
            <h3>Connection instructions</h3>

            <FormGroup floating label="SSH username" class="d-flex align-items-center">
                <input type="text" class="form-control" readonly value={sshUsername} />
                <CopyButton text={sshUsername} />
            </FormGroup>

            <FormGroup floating label="Example command" class="d-flex align-items-center">
                <input type="text" class="form-control" readonly value={exampleCommand} />
                <CopyButton text={exampleCommand} />
            </FormGroup>
        {/if}
    </ModalBody>
</Modal>

<style lang="scss">
    .target-item {
        display: flex;
        align-items: center;
    }
</style>
