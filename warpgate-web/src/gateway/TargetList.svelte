<script lang="ts">
    import {
        faArrowRight,
        faEllipsisV,
        faTerminal,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        Button,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
        Tooltip,
    } from '@sveltestrap/sveltestrap'
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import GettingStarted from 'common/GettingStarted.svelte'
    import { resolveGroup } from 'common/groups'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import {
        api,
        TargetClickAction,
        TargetKind,
        type TargetSnapshot,
    } from 'gateway/lib/api'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { get } from 'svelte/store'
    import Fa from 'svelte-fa'
    import { firstBy } from 'thenby'
    import {
        collapsedTargetGroups,
        openTargetsInNewTab,
        openTargetsInNewTabForced,
        serverInfo,
        setOpenTargetsInNewTab,
    } from './lib/store'
    import { openWebDesktopSession, openWebSshSession } from './lib/webSessions'

    let instructionsTarget: TargetSnapshot | undefined = $state()

    const canEditTargets = $derived(
        $serverInfo?.adminPermissions?.targetsEdit ?? false,
    )
    const webClientsEnabled = $derived($serverInfo?.webClientsEnabled ?? true)

    function loadTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<TargetSnapshot>> {
        return from(api.getTargets({ search: options.search })).pipe(
            map(result => {
                const naturalCompare = naturalCompareFactory()

                result = result.sort(
                    firstBy<TargetSnapshot, boolean>(
                        (x: TargetSnapshot) => !x.group,
                    )
                        // Natural sort between groups
                        .thenBy((a: TargetSnapshot, b: TargetSnapshot) =>
                            naturalCompare(
                                (a.group?.name ?? '').toLowerCase(),
                                (b.group?.name ?? '').toLowerCase(),
                            ),
                        )
                        // Natural sort within a group
                        .thenBy((a: TargetSnapshot, b: TargetSnapshot) =>
                            naturalCompare(
                                a.name.toLowerCase(),
                                b.name.toLowerCase(),
                            ),
                        ),
                )

                return {
                    items: result,
                    offset: 0,
                    total: result.length,
                }
            }),
        )
    }

    function urlForTarget(target: TargetSnapshot): string | undefined {
        if (target.kind === TargetKind.Http) {
            if (target.externalHost) {
                const port = location.port ? `:${location.port}` : ''
                return `${location.protocol}//${target.externalHost}${port}`
            } else {
                return `/?warpgate-target=${target.name}`
            }
        } else if (target.kind === TargetKind.Ssh) {
            return `/@warpgate/#/web-ssh/start/${target.id}`
        } else if (
            target.kind === TargetKind.Vnc ||
            target.kind === TargetKind.Rdp
        ) {
            return `/@warpgate/#/web-desktop/start/${target.id}`
        }
    }

    function selectTarget(target: TargetSnapshot) {
        if (target.kind === TargetKind.Http) {
            // biome-ignore lint/style/noNonNullAssertion: .
            loadURL(urlForTarget(target)!)
        } else if (target.kind === TargetKind.Ssh) {
            const targetClickAction = $serverInfo?.targetClickAction
            if (
                !webClientsEnabled ||
                targetClickAction === TargetClickAction.ShowInstructions
            ) {
                instructionsTarget = target
            } else {
                openWebSshSession(target.id)
            }
        } else if (
            target.kind === TargetKind.Vnc ||
            target.kind === TargetKind.Rdp
        ) {
            if (!webClientsEnabled) {
                instructionsTarget = target
            } else {
                openWebDesktopSession(target.id)
            }
        } else {
            instructionsTarget = target
        }
    }

    function showInstructions(target: TargetSnapshot) {
        instructionsTarget = target
    }

    function loadURL(url: string) {
        // Only HTTP targets navigate via loadURL. Honour the opt-in preference
        // to open them in a new tab (mirrors how SSH/desktop targets already
        // use window.open) so the target list isn't lost.
        if (get(openTargetsInNewTab)) {
            window.open(url, '_blank')
        } else {
            location.href = url
        }
    }

    function groupInfoFromTarget(target: TargetSnapshot) {
        return resolveGroup(target.group)
    }
</script>

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo?.setupState} />
{/if}

<ItemList
    load={loadTargets}
    showSearch={true}
    groupObject={groupInfoFromTarget}
    groupKey={group => group.id}
    bind:collapsedGroups={$collapsedTargetGroups}
>
    {#snippet header(items, groupControls)}
        {#if items?.length}
            <ListOverflowMenu {groupControls}>
                <div class="dropdown-header">Preferences</div>
                <DropdownItem>
                    <!-- A disabled input doesn't emit the pointer events the
                    tooltip needs, so the wrapper carries the target id. -->
                    <div id="openTargetsInNewTabSwitch">
                        <Input
                            type="switch"
                            checked={$openTargetsInNewTab}
                            disabled={$openTargetsInNewTabForced}
                            label="Open targets in a new tab"
                            onchange={e =>
                                setOpenTargetsInNewTab(
                                    (e.currentTarget as HTMLInputElement).checked,
                                )}
                            onmousedown={e => e.stopPropagation()}
                        />
                    </div>
                    {#if $openTargetsInNewTabForced}
                        <Tooltip
                            delay="250"
                            target="openTargetsInNewTabSwitch"
                            animation
                        >
                            Managed by the administrator
                        </Tooltip>
                    {/if}
                </DropdownItem>
            </ListOverflowMenu>
        {/if}
    {/snippet}
    {#snippet empty()}
        <EmptyState title="You don't have access to any targets yet" />
    {/snippet}
    {#snippet groupHeader(group, state)}
        <CollapsibleGroupHeader {group} {state} />
    {/snippet}
    {#snippet item(target)}
        <a
            class="list-group-item list-group-item-action target-item gap-3"
            href={urlForTarget(target)}
            target={target.kind === TargetKind.Http && $openTargetsInNewTab
                ? '_blank'
                : undefined}
            onclick={e => {
                if (e.metaKey || e.ctrlKey) {
                    return
                }
                e.preventDefault()
                e.stopPropagation()
                selectTarget(target)
            }}
        >
            <span class="me-auto">
                <div class="d-flex align-items-center gap-2">
                    {target.name}
                </div>
                {#if target.description}
                    <small class="d-block text-muted"
                        >{target.description}</small
                    >
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
                {#if target.kind === TargetKind.Vnc}
                    VNC
                {/if}
                {#if target.kind === TargetKind.Rdp}
                    RDP
                {/if}
            </small>
            {#if target.kind === TargetKind.Http}
                <Button color="link" size="sm" tabindex={-1}>
                    <Fa icon={faArrowRight} fw />
                </Button>
            {/if}
            <Dropdown>
                <DropdownToggle
                    color="link"
                    size="sm"
                    onclick={e => {
                    e.preventDefault()
                    e.stopPropagation()
                }}
                >
                    <Fa icon={faEllipsisV} fw />
                </DropdownToggle>
                <DropdownMenu end>
                    {#if target.kind === TargetKind.Ssh && webClientsEnabled}
                        <DropdownItem
                            onclick={e => {
                            openWebSshSession(target.id)
                            e.preventDefault()
                            e.stopPropagation()
                        }}
                        >
                            Web terminal
                        </DropdownItem>
                    {/if}
                    {#if (target.kind === TargetKind.Vnc || target.kind === TargetKind.Rdp) && webClientsEnabled}
                        <DropdownItem
                            onclick={e => {
                            openWebDesktopSession(target.id)
                            e.preventDefault()
                            e.stopPropagation()
                        }}
                        >
                            Web desktop
                        </DropdownItem>
                    {/if}
                    <DropdownItem
                        onclick={e => {
                        showInstructions(target)
                        e.preventDefault()
                        e.stopPropagation()
                    }}
                    >
                        Connection instructions
                    </DropdownItem>
                    {#if canEditTargets}
                        <DropdownItem
                            href={`/@warpgate/admin#/config/targets/${target.id}`}
                            onclick={e => e.stopPropagation()}
                        >
                            Edit target
                        </DropdownItem>
                    {/if}
                </DropdownMenu>
            </Dropdown>
        </a>
    {/snippet}
</ItemList>

{#if $serverInfo?.setupState && !$serverInfo.setupState.hasTargets}
    <EmptyState
        hint="Once you add targets and assign access, they will appear here"
        title="No other targets yet"
    />
{/if}

<Modal
    isOpen={!!instructionsTarget}
    toggle={() => instructionsTarget = undefined}
    size="lg"
>
    <ModalBody>
        {#if instructionsTarget}
            <ConnectionInstructions
                targetName={instructionsTarget.name}
                username={$serverInfo?.username}
                targetKind={instructionsTarget.kind ?? TargetKind.Ssh}
                targetDefaultDatabaseName={(instructionsTarget.kind === TargetKind.MySql || instructionsTarget.kind === TargetKind.Postgres)
                    ? instructionsTarget.defaultDatabaseName : undefined}
            />
        {/if}
    </ModalBody>
    <ModalFooter>
        {#if instructionsTarget?.kind === TargetKind.Ssh && webClientsEnabled}
            {@const sshTarget = instructionsTarget}
            <Button
                color="primary"
                class="d-flex align-items-center justify-content-center gap-2 modal-button"
                onclick={() => openWebSshSession(sshTarget.id)}
            >
                <Fa icon={faTerminal} />
                Web terminal
            </Button>
        {/if}
        <Button
            color="secondary"
            class="modal-button"
            block
            on:click={() => { instructionsTarget = undefined }}
        >
            Close
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    .target-item {
        display: flex;
        align-items: center;
        cursor: pointer;
    }
</style>
