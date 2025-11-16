<script lang="ts">
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { api, type TargetSnapshot, TargetKind } from 'gateway/lib/api'
import Fa from 'svelte-fa'
import { Button, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'
import GettingStarted from 'common/GettingStarted.svelte'

function getBootstrapColorValue(color: string | undefined): string {
    if (!color) return '#6c757d' // Bootstrap secondary/default gray
    const colorMap: Record<string, string> = {
        primary: '#0d6efd',
        secondary: '#6c757d',
        success: '#198754',
        danger: '#dc3545',
        warning: '#ffc107',
        info: '#0dcaf0',
        light: '#f8f9fa',
        dark: '#212529',
    }
    return colorMap[color] || '#6c757d'
}

let selectedTarget: TargetSnapshot|undefined = $state()
let targets: TargetSnapshot[] = $state([])
let groupedTargets: { [groupName: string]: TargetSnapshot[] } = $state({})
let searchQuery = $state('')
let filteredTargets: TargetSnapshot[] = $state([])
let filteredGroupedTargets: { [groupName: string]: TargetSnapshot[] } = $state({})

// Simple data loading
api.getTargets({}).then(result => {
    targets = result.sort(
        firstBy<TargetSnapshot, boolean>(x => x.kind !== TargetKind.WebAdmin)
            .thenBy(x => x.name.toLowerCase())
    )

    // Group targets by group name, but handle WebAdmin specially
    groupedTargets = {}
    let webAdminTarget: TargetSnapshot | undefined = undefined

    for (const target of targets) {
        if (target.kind === TargetKind.WebAdmin) {
            webAdminTarget = target
        } else {
            const groupName = target.group?.name || 'Ungrouped'
            if (!groupedTargets[groupName]) {
                groupedTargets[groupName] = []
            }
            groupedTargets[groupName].push(target)
        }
    }

    // Add WebAdmin target to its own special section
    if (webAdminTarget) {
        groupedTargets['Administration'] = [webAdminTarget]
    }

    // Initialize filtered results
    filteredTargets = targets
    filteredGroupedTargets = groupedTargets
}).catch(e => {
    console.error('Failed to load targets:', e)
})

function selectTarget (target: TargetSnapshot) {
    if (target.kind === TargetKind.WebAdmin) {
        loadURL('/@warpgate/admin')
    } else if (target.kind === TargetKind.Http) {
        loadURL(`/?warpgate-target=${target.name}`)
    } else {
        selectedTarget = target
    }
}

function loadURL (url: string) {
    location.href = url
}

function filterTargets() {
    if (!searchQuery.trim()) {
        filteredTargets = targets
        filteredGroupedTargets = groupedTargets
        return
    }

    const query = searchQuery.toLowerCase().trim()
    filteredTargets = targets.filter(target =>
        target.name.toLowerCase().includes(query) ||
        target.description.toLowerCase().includes(query)
    )

    // Re-group filtered targets
    filteredGroupedTargets = {}
    let webAdminTarget: TargetSnapshot | undefined = undefined

    for (const target of filteredTargets) {
        if (target.kind === TargetKind.WebAdmin) {
            webAdminTarget = target
        } else {
            const groupName = target.group?.name || 'Ungrouped'
            if (!filteredGroupedTargets[groupName]) {
                filteredGroupedTargets[groupName] = []
            }
            filteredGroupedTargets[groupName].push(target)
        }
    }

    // Add WebAdmin target to its own special section
    if (webAdminTarget) {
        filteredGroupedTargets['Administration'] = [webAdminTarget]
    }
}

</script>

{#if $serverInfo?.setupState}
    <GettingStarted
        setupState={$serverInfo?.setupState} />
{/if}

<div class="search-container mb-3">
    <div class="input-group">
        <input
            type="text"
            class="form-control"
            placeholder="Search targets..."
            bind:value={searchQuery}
            oninput={filterTargets}
        />
        {#if searchQuery}
            <button
                class="btn btn-outline-secondary"
                type="button"
                onclick={() => {
                    searchQuery = ''
                    filterTargets()
                }}
            >
                Clear
            </button>
        {/if}
    </div>
</div>

<div class="targets-container">
    {#if Object.keys(filteredGroupedTargets).length === 0 && searchQuery}
        <div class="text-center text-muted py-4">
            <p>No targets found matching "{searchQuery}"</p>
            <button
                class="btn btn-outline-secondary btn-sm"
                onclick={() => {
                    searchQuery = ''
                    filterTargets()
                }}
            >
                Clear search
            </button>
        </div>
    {:else}
        {#each Object.entries(filteredGroupedTargets).sort(([a], [b]) => {
            // Administration section always comes first
            if (a === 'Administration') return -1
            if (b === 'Administration') return 1
            return a.localeCompare(b)
        }) as [groupName, groupTargets]}
        <div class="target-group">
            <div class="group-header" class:administration={groupName === 'Administration'} style:background-color={groupName === 'Administration' ? '#dc3545' : getBootstrapColorValue(groupTargets[0]?.group?.color)}>
                <h6 class="group-title">{groupName}</h6>
            </div>
            <div class="list-group">
                {#each groupTargets as target}
                    <a
                        class="list-group-item list-group-item-action target-item"
                        href={
                            target.kind === TargetKind.WebAdmin
                                ? '/@warpgate/admin'
                                : target.kind === TargetKind.Http
                                    ? `/?warpgate-target=${target.name}`
                                    : '/@warpgate/admin'
                        }
                        onclick={e => {
                            if (e.metaKey || e.ctrlKey) {
                                return
                            }
                            e.preventDefault()
                            selectTarget(target)
                        }}
                    >
                        <span class="me-auto">
                            {#if target.kind === TargetKind.WebAdmin}
                                Manage Warpgate
                            {:else}
                                <div>
                                    {target.name}
                                </div>
                                {#if target.description}
                                    <small class="d-block text-muted">{target.description}</small>
                                {/if}
                            {/if}
                        </span>
                        <small class="protocol text-muted ms-auto">
                            {#if target.kind === TargetKind.Ssh}
                                SSH
                            {/if}
                            {#if target.kind === TargetKind.MySql}
                                MySQL
                            {/if}
                            {#if target.kind === TargetKind.Postgres}
                                PostgreSQL
                            {/if}
                        </small>
                        {#if target.kind === TargetKind.Http || target.kind === TargetKind.WebAdmin}
                            <Fa icon={faArrowRight} fw />
                        {/if}
                    </a>
                {/each}
            </div>
        </div>
        {/each}
    {/if}
</div>

<Modal isOpen={!!selectedTarget} toggle={() => selectedTarget = undefined}>
    <ModalBody>
        <ConnectionInstructions
            targetName={selectedTarget?.name}
            username={$serverInfo?.username}
            targetKind={selectedTarget?.kind ?? TargetKind.Ssh}
        />
    </ModalBody>
    <ModalFooter>
        <Button
            color="secondary"
            class="modal-button"
            block
            on:click={() => { selectedTarget = undefined }}
        >
            Close
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    .search-container {
        .input-group {
            max-width: 400px;
        }
    }

    .targets-container {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    .target-group {
        display: flex;
        flex-direction: column;
    }

    .group-header {
        background-color: #6c757d;
        color: white;
        padding: 0.75rem 1rem;
        border-radius: 0.375rem 0.375rem 0 0;
        margin-bottom: 0;
    }

    .group-header.administration {
        background-color: #dc3545 !important;
        font-weight: 700;
    }

    .group-title {
        margin: 0;
        font-size: 0.875rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .list-group {
        border-radius: 0 0 0.375rem 0.375rem;
        border: 1px solid #dee2e6;
        border-top: none;
    }

    .list-group-item {
        transition: background-color 0.2s ease-in-out;

        &:hover {
            background-color: #f8f9fa;
            color: #212529;

            .text-muted {
                color:rgb(29, 30, 31) !important;
            }
        }

        &:first-child {
            border-top: none;
        }
    }
</style>
