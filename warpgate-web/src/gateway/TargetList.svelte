<script lang="ts">
import { Observable, from, map } from 'rxjs'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
import { api, type TargetSnapshot, TargetKind } from 'gateway/lib/api'
import Fa from 'svelte-fa'
import { Button, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'
import GettingStarted from 'common/GettingStarted.svelte'
import EmptyState from 'common/EmptyState.svelte'
import { makeTargetURL } from 'common/protocols'

let selectedTarget: TargetSnapshot|undefined = $state()

function loadTargets (options: LoadOptions): Observable<PaginatedResponse<TargetSnapshot>> {
    return from(api.getTargets({ search: options.search })).pipe(
        map(result => {
            result = result.sort(
                firstBy<TargetSnapshot, boolean>(x => x.kind !== TargetKind.WebAdmin)
                    .thenBy(x => x.name.toLowerCase())
            )
            return {
                items: result,
                offset: 0,
                total: result.length,
            }
        })
    )
}

function getTargetURL (target: TargetSnapshot): string | null {
    if (target.kind === TargetKind.WebAdmin) {
        return '/@warpgate/admin'
    } else if (target.kind === TargetKind.Http) {
        return makeTargetURL({
            serverInfo: $serverInfo,
            targetName: target.name,
            targetExternalHost: target.externalHost,
        })
    }
    return null
}

function selectTarget (target: TargetSnapshot) {
    const url = getTargetURL(target)
    if (url) {
        location.href = url
        return
    }
    selectedTarget = target
}

</script>

{#if $serverInfo?.setupState}
    <GettingStarted
        setupState={$serverInfo?.setupState} />
{/if}

<ItemList load={loadTargets} showSearch={true}>
    {#snippet empty()}
        <EmptyState
            title="You don't have access to any targets yet" />
    {/snippet}
    {#snippet item(target)}
        <a
            class="list-group-item list-group-item-action target-item"
            href={getTargetURL(target)}
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
