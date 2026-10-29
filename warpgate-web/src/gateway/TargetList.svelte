<script lang="ts">
    import 'core-js/actual/map/group-by'

    import { faClipboard } from '@fortawesome/free-regular-svg-icons'
    import {
        faArrowRight,
        faDesktop,
        faEllipsisV,
        faTerminal,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        Alert,
        Button,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
        Tooltip,
    } from '@sveltestrap/sveltestrap'
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import GettingStarted from 'common/GettingStarted.svelte'
    import { orderForGroupedList, resolveGroup } from 'common/groups'
    import ItemList, {
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import { TARGET_KIND_LABELS } from 'common/targetKinds'
    import {
        api,
        TargetClickAction,
        TargetKind,
        type TargetSnapshot,
    } from 'gateway/lib/api'
    import { from, map, type Observable } from 'rxjs'
    import { get } from 'svelte/store'
    import Fa from 'svelte-fa'
    import {
        collapsedTargetGroups,
        openTargetsInNewTab,
        openTargetsInNewTabForced,
        serverInfo,
        setOpenTargetsInNewTab,
    } from './lib/store'
    import {
        openWebDesktopSession,
        openWebSshSession,
        webDesktopUrl,
        webSshUrl,
    } from './lib/webSessions'

    let instructionsTarget: TargetSnapshot | undefined = $state()
    // The target an in-browser session is being opened for. Opening one can
    // take as long as an administrator takes to approve it, and until then
    // there is nothing else on screen to say the click did anything.
    let openingTarget: TargetSnapshot | undefined = $state()
    let openError: string | undefined = $state()

    const canEditTargets = $derived(
        $serverInfo?.adminPermissions?.targetsEdit ?? false,
    )
    const webClientsEnabled = $derived($serverInfo?.webClientsEnabled ?? true)

    function loadTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<TargetSnapshot>> {
        return from(api.getTargets({ search: options.search })).pipe(
            map(result => {
                const items = orderForGroupedList(result, options.search, {
                    groupId: t => t.group?.id,
                    groupName: t => t.group?.name ?? '',
                    name: t => t.name,
                })
                return { items, offset: 0, total: items.length }
            }),
        )
    }

    function httpTargetUrl(target: TargetSnapshot): string {
        if (target.externalHost) {
            const port = location.port ? `:${location.port}` : ''
            return `${location.protocol}//${target.externalHost}${port}`
        }
        return `/?warpgate-target=${encodeURIComponent(target.name)}`
    }

    // What a click on the row does: the row shows the label, links to href
    // (so middle-click and "open in new tab" go to the same place) and runs
    // run() on a plain click. Targets without an href open their
    // connection instructions.
    function rowAction(target: TargetSnapshot) {
        if (target.kind === TargetKind.Http) {
            const href = httpTargetUrl(target)
            return {
                label: 'Open',
                icon: faArrowRight,
                href,
                run: () => loadURL(href),
            }
        }
        if (
            target.kind === TargetKind.Ssh &&
            webClientsEnabled &&
            $serverInfo?.targetClickAction !==
                TargetClickAction.ShowInstructions
        ) {
            return {
                label: 'Open terminal',
                icon: faTerminal,
                href: webSshUrl(target.id),
                run: () =>
                    void openInBrowser(target, () =>
                        openWebSshSession(target.id),
                    ),
            }
        }
        if (
            (target.kind === TargetKind.Vnc ||
                target.kind === TargetKind.Rdp) &&
            webClientsEnabled
        ) {
            return {
                label: 'Open desktop',
                icon: faDesktop,
                href: webDesktopUrl(target.id),
                run: () => openWebDesktopSession(target.id),
            }
        }
        return {
            label: 'Connection info',
            icon: faClipboard,
            href: undefined,
            run: () => showInstructions(target),
        }
    }

    // A target that needs administrator approval holds this until someone
    // decides, and answers 403 if they say no — so it needs both a sign that
    // it is in progress and somewhere for the refusal to land.
    async function openInBrowser(
        target: TargetSnapshot,
        open: () => void | Promise<void>,
    ) {
        openError = undefined
        openingTarget = target
        try {
            await open()
        } catch (err) {
            openError = await stringifyError(err)
        } finally {
            openingTarget = undefined
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

{#if openingTarget}
    <Alert color="info">
        Connecting to {openingTarget.name}. If this target needs approval, it
        will start once an administrator approves it.
    </Alert>
{/if}

{#if openError}
    <Alert color="danger">{openError}</Alert>
{/if}

<ItemList
    load={loadTargets}
    showSearch={true}
    groupObject={groupInfoFromTarget}
    groupKey={group => group.id}
    bind:collapsedGroups={$collapsedTargetGroups}
    virtual
>
    {#snippet header(
        items,
        groupControls,
    )}
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
                                    (e.currentTarget as HTMLInputElement)
                                        .checked,
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
        <EmptyState
            title="You don't have access to any targets yet"
            hint={`Ask an administrator to give ${$serverInfo?.username ?? 'your account'} a role with the targets you need.`}
        />
    {/snippet}
    {#snippet groupHeader(
        group,
        state,
    )}
        <CollapsibleGroupHeader {group} {state} />
    {/snippet}
    {#snippet item(
        target,
    )}
        {@const action = rowAction(target)}
        <div class="list-group-item list-group-item-action target-item">
            <a
                class="target-main"
                href={action.href}
                target={target.kind === TargetKind.Http && $openTargetsInNewTab
                    ? '_blank'
                    : undefined}
                role={action.href ? undefined : 'button'}
                tabindex={action.href ? undefined : 0}
                onclick={e => {
                    // Let the browser handle new-tab and new-window clicks
                    if (
                        e.metaKey ||
                        e.ctrlKey ||
                        e.shiftKey ||
                        e.button !== 0
                    ) {
                        return
                    }
                    e.preventDefault()
                    action.run()
                }}
                onkeydown={e => {
                    // Rows without an href are not links, so Enter and Space
                    // have to be handled here
                    if (!action.href && (e.key === 'Enter' || e.key === ' ')) {
                        e.preventDefault()
                        action.run()
                    }
                }}
            >
                <span class="target-name">{target.name}</span>
                {#if target.description}
                    <span class="target-description">{target.description}</span>
                {/if}
                <span class="target-kind-inline"
                    >{TARGET_KIND_LABELS[target.kind]}</span
                >
                <span class="visually-hidden">{action.label}</span>
            </a>
            <span class="target-kind">{TARGET_KIND_LABELS[target.kind]}</span>
            <span class="target-action" aria-hidden="true">
                <Fa icon={action.icon} fw />
                <span class="target-action-label">{action.label}</span>
            </span>
            <Dropdown class="target-menu">
                <DropdownToggle
                    color="link"
                    size="sm"
                    aria-label={`More actions for ${target.name}`}
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
                                void openInBrowser(target, () =>
                                    openWebSshSession(target.id),
                                )
                                e.preventDefault()
                                e.stopPropagation()
                            }}
                        >
                            Web terminal
                        </DropdownItem>
                    {/if}
                    {#if (target.kind === TargetKind.Vnc ||
                        target.kind === TargetKind.Rdp) &&
                        webClientsEnabled}
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
        </div>
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
    toggle={() => (instructionsTarget = undefined)}
    size="lg"
>
    {#if instructionsTarget}
        <ModalHeader>Connect to {instructionsTarget.name}</ModalHeader>
    {/if}
    <ModalBody>
        {#if instructionsTarget}
            <ConnectionInstructions
                targetName={instructionsTarget.name}
                username={$serverInfo?.username}
                targetKind={instructionsTarget.kind ?? TargetKind.Ssh}
                targetDefaultDatabaseName={instructionsTarget.kind ===
                    TargetKind.MySql ||
                instructionsTarget.kind === TargetKind.Postgres
                    ? instructionsTarget.defaultDatabaseName
                    : undefined}
            />
        {/if}
    </ModalBody>
    <ModalFooter>
        {#if instructionsTarget?.kind === TargetKind.Ssh && webClientsEnabled}
            {@const sshTarget = instructionsTarget}
            <Button
                color="primary"
                class="d-flex align-items-center justify-content-center gap-2 modal-button"
                onclick={() =>
                    openInBrowser(sshTarget, () =>
                        openWebSshSession(sshTarget.id),
                    )}
            >
                <Fa icon={faTerminal} />
                Web terminal
            </Button>
        {/if}
        <Button
            color="secondary"
            class="modal-button"
            block
            on:click={() => {
                instructionsTarget = undefined
            }}
        >
            Close
        </Button>
    </ModalFooter>
</Modal>

<style lang="scss">
    // One line per target: name, description, kind, the click's action and
    // a menu. The main link stretches over the row; the rest sits above it.
    .target-item {
        position: relative;
        display: flex;
        align-items: center;
        gap: 1rem;
        padding-top: 0.45rem;
        padding-bottom: 0.45rem;

        // An open menu must cover the rows below it
        &:has(:global(.dropdown-menu.show)) {
            z-index: 3;
        }
    }

    .target-main {
        flex: 1;
        min-width: 0;
        display: flex;
        align-items: baseline;
        gap: 1.5rem;
        color: inherit;
        text-decoration: none;
        cursor: pointer;

        &::after {
            content: '';
            position: absolute;
            inset: 0;
        }

        &:focus-visible {
            outline: none;

            &::after {
                outline: 2px solid var(--bs-primary);
                outline-offset: -2px;
            }
        }
    }

    .target-name {
        flex: 0 0 16rem;
        color: var(--bs-emphasis-color);
        font-weight: 500;
        overflow-wrap: anywhere;
    }

    .target-description {
        flex: 1;
        min-width: 0;
        color: var(--bs-secondary-color);
        font-size: 0.875rem;
        display: -webkit-box;
        -webkit-box-orient: vertical;
        -webkit-line-clamp: 2;
        line-clamp: 2;
        overflow: hidden;
    }

    .target-kind,
    .target-kind-inline {
        font-size: 0.8125rem;
        color: var(--bs-secondary-color);
        white-space: nowrap;
    }

    .target-kind-inline {
        display: none;
    }

    .target-action {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        min-width: 9.5rem;
        font-size: 0.875rem;
        color: var(--bs-secondary-color);
        white-space: nowrap;
    }

    .target-item:hover .target-action,
    .target-main:focus-visible ~ .target-action {
        color: var(--bs-emphasis-color);

        .target-action-label {
            text-decoration: underline;
            text-underline-offset: 2px;
        }
    }

    // Drawn after the stretched link, so they sit above it without a
    // z-index of their own; the menu is a .dropdown, already relative
    .target-kind,
    .target-action {
        position: relative;
        pointer-events: none;
    }

    @media (max-width: 991px) {
        .target-main {
            flex-direction: column;
            gap: 0;
        }

        .target-name {
            flex: none;
        }

        .target-kind,
        .target-action-label {
            display: none;
        }

        .target-kind-inline {
            display: block;
        }

        .target-action {
            min-width: 0;
        }

        .target-item :global(.target-menu .btn) {
            min-width: 44px;
            min-height: 44px;
        }
    }
</style>
