<script lang="ts">
import { Observable, from, map } from 'rxjs'
import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import ItemList, { LoadOptions, PaginatedResponse } from 'common/ItemList.svelte'
import { api, TargetSnapshot, TargetKind } from 'gateway/lib/api'
import { createEventDispatcher } from 'svelte'
import Fa from 'svelte-fa'
import { Modal, ModalBody, ModalHeader } from 'sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'

const dispatch = createEventDispatcher()

let selectedTarget: TargetSnapshot|undefined

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
    dispatch('navigation')
    location.href = url
}

</script>

<ItemList load={loadTargets} showSearch={true}>
    <a
        slot="item" let:item={target}
        class="list-group-item list-group-item-action target-item"
        href={
            target.kind === TargetKind.WebAdmin
            ? '/@warpgate/admin'
            : target.kind === TargetKind.Http
            ? `/?warpgate-target=${target.name}`
            : '/@warpgate/admin'
        }
        on:click|preventDefault={e => {
            if (e.metaKey || e.ctrlKey) {
                return
            }
            selectTarget(target)
        }}
    >
        <span class="me-auto">
            {#if target.kind === TargetKind.WebAdmin}
                Manage Warpgate
            {:else}
                {target.name}
            {/if}
        </span>
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
