<script lang="ts">
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { api, TargetSnapshot, TargetKind } from 'gateway/lib/api'
import { createEventDispatcher } from 'svelte'
import Fa from 'svelte-fa'
import { Modal, ModalBody, ModalHeader, Spinner } from 'sveltestrap'
import { serverInfo } from './lib/store'

const dispatch = createEventDispatcher()

let targets: TargetSnapshot[]|undefined
let selectedTarget: TargetSnapshot|undefined

async function init () {
    targets = await api.getTargets()
}

function selectTarget (target: TargetSnapshot) {
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
                {#if target.kind === TargetKind.MySql}
                    MySQL
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
        <h3>Connection instructions</h3>
        <ConnectionInstructions
            targetName={selectedTarget?.name}
            username={$serverInfo?.username}
            targetKind={selectedTarget?.kind ?? TargetKind.Ssh}
        />
    </ModalBody>
</Modal>

<style lang="scss">
    .target-item {
        display: flex;
        align-items: center;
    }
</style>
