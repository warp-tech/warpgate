<script lang="ts">
import { Observable, from, map } from 'rxjs'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
import { api, type TargetSnapshot, TargetKind } from 'gateway/lib/api'
import Fa from 'svelte-fa'
import { Modal, ModalBody } from '@sveltestrap/sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'
import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'

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

</script>

<ItemList load={loadTargets} showSearch={true}>
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
