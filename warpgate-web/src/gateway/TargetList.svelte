<script lang="ts">
import { Observable, from, map } from 'rxjs'
import { compare as naturalCompare } from 'natural-orderby'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
import { api, type TargetSnapshot, TargetKind, BootstrapThemeColor } from 'gateway/lib/api'
import Fa from 'svelte-fa'
import { Button, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'
import GettingStarted from 'common/GettingStarted.svelte'
import EmptyState from 'common/EmptyState.svelte'
import GroupColorCircle from 'common/GroupColorCircle.svelte'

let selectedTarget: TargetSnapshot|undefined = $state()

function loadTargets (options: LoadOptions): Observable<PaginatedResponse<TargetSnapshot>> {
    return from(api.getTargets({ search: options.search })).pipe(
        map(result => {
            result = result.sort(
                firstBy<TargetSnapshot, boolean>(x => x.kind !== TargetKind.WebAdmin)
                    .thenBy<TargetSnapshot, boolean>(x => !x.group)
                    .thenBy<TargetSnapshot, string | undefined>(x => x.group?.name.toLowerCase())
                    .thenBy((a, b) =>
                        naturalCompare(a.name.toLowerCase(), b.name.toLowerCase()))
            )
            return {
                items: result,
                offset: 0,
                total: result.length,
            }
        })
    )
}

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

interface GroupInfo {
    id: string
    name: string
    color: BootstrapThemeColor
}

function groupInfoFromTarget (target: TargetSnapshot): GroupInfo {
    if (target.kind === TargetKind.WebAdmin) {
        return {
            id: '$admin',
            name: 'Administration',
            color: BootstrapThemeColor.Danger,
        }
    }
    if (!target.group) {
        return {
            id: '$ungrouped',
            name: 'Ungrouped',
            color: BootstrapThemeColor.Secondary,
        }
    }
    return {
        id: target.group.id,
        name: target.group.name,
        color: target.group.color ?? BootstrapThemeColor.Secondary,
    }
}

</script>

{#if $serverInfo?.setupState}
    <GettingStarted
        setupState={$serverInfo?.setupState} />
{/if}

<ItemList load={loadTargets} showSearch={true} groupObject={groupInfoFromTarget} groupKey={group => group.id}>
    {#snippet empty()}
        <EmptyState
            title="You don't have access to any targets yet" />
    {/snippet}
    {#snippet groupHeader(group)}
        <div class="d-flex align-items-center gap-2 mb-2 mt-4">
            <GroupColorCircle color={group.color} />
            <div class="h5 mb-0">{group.name}</div>
        </div>
    {/snippet}
    {#snippet item(target)}
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
                    <div class="d-flex align-items-center gap-2">
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
    {/snippet}
</ItemList>

{#if $serverInfo?.setupState && !$serverInfo.setupState.hasTargets}
    <EmptyState
        hint="Once you add targets and assign access, they will appear here"
        title="No other targets yet" />
{/if}

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
    .target-item {
        display: flex;
        align-items: center;
    }
</style>
