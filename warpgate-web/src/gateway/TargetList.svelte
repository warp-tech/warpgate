<script lang="ts">
import { Observable, from, map } from 'rxjs'
import { compare as naturalCompareFactory } from 'natural-orderby'
import { faArrowRight, faEllipsisV, faTerminal } from '@fortawesome/free-solid-svg-icons'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import ItemList, { type LoadOptions, type PaginatedResponse } from 'common/ItemList.svelte'
import { api, type TargetSnapshot, TargetKind, BootstrapThemeColor } from 'gateway/lib/api'
import Fa from 'svelte-fa'
import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownToggle, Modal, ModalBody, ModalFooter } from '@sveltestrap/sveltestrap'
import { serverInfo } from './lib/store'
import { firstBy } from 'thenby'
import GettingStarted from 'common/GettingStarted.svelte'
import EmptyState from 'common/EmptyState.svelte'
import GroupColorCircle from 'common/GroupColorCircle.svelte'

let selectedTarget: TargetSnapshot|undefined = $state()

async function openWebSsh (target: TargetSnapshot) {
    const { sessionId } = await api.createWebSshSession({
        createWebSshSessionBody: { targetId: target.id },
    })
    window.open(`/@warpgate#/web-ssh/${sessionId}`, '_blank')
}

function loadTargets(
    options: LoadOptions
): Observable<PaginatedResponse<TargetSnapshot>> {
    return from(api.getTargets({ search: options.search })).pipe(
        map(result => {
            const naturalCompare = naturalCompareFactory()

            result = result.sort(
                firstBy<TargetSnapshot, boolean>((x: TargetSnapshot) => !x.group)
                    // Natural sort between groups
                    .thenBy((a: TargetSnapshot, b: TargetSnapshot) =>
                        naturalCompare(
                            (a.group?.name ?? '').toLowerCase(),
                            (b.group?.name ?? '').toLowerCase()
                        )
                    )
                    // Natural sort within a group
                    .thenBy((a: TargetSnapshot, b: TargetSnapshot) =>
                        naturalCompare(
                            a.name.toLowerCase(),
                            b.name.toLowerCase()
                        )
                    )
            )

            return {
                items: result,
                offset: 0,
                total: result.length,
            }
        }),
    )
}

function selectTarget (target: TargetSnapshot) {
    if (target.kind === TargetKind.Http) {
        if (target.externalHost) {
            const port = location.port ? `:${location.port}` : ''
            loadURL(`${location.protocol}//${target.externalHost}${port}`)
        } else {
            loadURL(`/?warpgate-target=${target.name}`)
        }
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
            class="list-group-item list-group-item-action target-item gap-3"
            href={
                target.kind === TargetKind.Http
                    ? (target.externalHost
                        ? `${location.protocol}//${target.externalHost}${location.port ? `:${location.port}` : ''}`
                        : `/?warpgate-target=${target.name}`)
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
                <div class="d-flex align-items-center gap-2">
                        {target.name}
                    </div>
                    {#if target.description}
                        <small class="d-block text-muted">{target.description}</small>
                    {/if}
            </span>
            <small class="protocol text-muted ms-auto">
                {#if target.kind === TargetKind.MySql}
                    MySQL
                {/if}
                {#if target.kind === TargetKind.Postgres}
                    PostgreSQL
                {/if}
                {#if target.kind === TargetKind.Kubernetes}
                    Kubernetes
                {/if}
                {#if target.kind === TargetKind.Ssh}
                    SSH
                {/if}
            </small>
            {#if target.kind === TargetKind.Ssh}
                <Dropdown>
                    <DropdownToggle color="link" size="sm" onclick={e => {
                        e.preventDefault()
                        e.stopPropagation()
                    }}>
                        <Fa icon={faEllipsisV} fw />
                    </DropdownToggle>
                    <DropdownMenu end>
                        <DropdownItem onclick={() => openWebSsh(target)}>Web terminal</DropdownItem>
                        <DropdownItem onclick={() => { selectedTarget = target }}>Connection instructions</DropdownItem>
                    </DropdownMenu>
                </Dropdown>
            {:else if target.kind === TargetKind.Http}
                <Button color="link" size="sm" tabindex={-1}>
                    <Fa icon={faArrowRight} fw />
                </Button>
            {:else}
                <Button disabled color="link" size="sm" tabindex={-1} style="visibility: hidden">
                    <Fa icon={faEllipsisV} fw />
                </Button>
            {/if}
        </a>
    {/snippet}
</ItemList>

{#if $serverInfo?.setupState && !$serverInfo.setupState.hasTargets}
    <EmptyState
        hint="Once you add targets and assign access, they will appear here"
        title="No other targets yet" />
{/if}

<Modal isOpen={!!selectedTarget} toggle={() => selectedTarget = undefined} size="lg">
    <ModalBody>
        {#if selectedTarget}
        <ConnectionInstructions
            targetName={selectedTarget.name}
            username={$serverInfo?.username}
            targetKind={selectedTarget.kind ?? TargetKind.Ssh}
            targetDefaultDatabaseName={
                (selectedTarget.kind === TargetKind.MySql || selectedTarget.kind === TargetKind.Postgres)
                    ? selectedTarget.defaultDatabaseName : undefined}
        />
        {/if}
    </ModalBody>
    <ModalFooter>
        {#if selectedTarget?.kind === TargetKind.Ssh}
            <Button
                color="primary"
                class="d-flex align-items-center justify-content-center gap-2 modal-button"
                onclick={() => openWebSsh(selectedTarget!)}
            >
                <Fa icon={faTerminal} />
                Open Web Terminal
            </Button>
        {/if}
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
