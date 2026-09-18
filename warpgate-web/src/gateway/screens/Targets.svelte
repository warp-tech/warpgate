<script lang="ts">
    /**
     * My targets — screen 13.
     *
     * ── Enumeration of gateway/TargetList.svelte, asserted present ───────
     * Load:     getTargets({ search }) with the same three-level natural sort
     *           — ungrouped first, then by group name, then by target name.
     * Stores:   collapsedTargetGroups, openTargetsInNewTab,
     *           openTargetsInNewTabForced, setOpenTargetsInNewTab.
     * Gates:    canEditTargets from serverInfo.adminPermissions.targetsEdit;
     *           webClientsEnabled from serverInfo.webClientsEnabled, default
     *           true.
     * urlForTarget: HTTP -> externalHost carrying location.port, else
     *           `/?warpgate-target=<name>`; SSH -> #/web-ssh/start/<id>;
     *           VNC and RDP -> #/web-desktop/start/<id>.
     * selectTarget: HTTP navigates; SSH shows instructions when web clients
     *           are off OR targetClickAction is ShowInstructions, otherwise
     *           opens the web terminal; VNC/RDP show instructions when web
     *           clients are off, otherwise open the web desktop; anything
     *           else shows instructions.
     * openInBrowser: sets openingTarget, surfaces a failure into openError,
     *           clears in `finally`. A target behind approval holds this until
     *           an administrator decides and answers 403 if they refuse, so
     *           it needs both a sign of progress and somewhere for the
     *           refusal to land.
     * loadURL:  honours openTargetsInNewTab for HTTP targets.
     * Row:      name, description, protocol label for all six kinds,
     *           ctrl/cmd-click falls through to the browser so a target can
     *           still be opened in a new tab, and `target="_blank"` on HTTP
     *           rows when the preference is set.
     * Menu:     Web terminal (SSH + web clients), Web desktop (VNC/RDP + web
     *           clients), Connection instructions, Edit target (when
     *           canEditTargets).
     * Modal:    ConnectionInstructions with the defaultDatabaseName plumbing,
     *           a Web terminal action for SSH, and Close.
     * Chrome:   GettingStarted when setupState is present; the
     *           "no other targets yet" empty state when setupState says there
     *           are none; the access empty state otherwise.
     *
     * ── Cards, with the fields that exist ────────────────────────────────
     * The mockup's card grid suits a portal — a handful of items, roomier
     * than an admin table — so the shape is kept. Its contents mostly cannot
     * be: `TargetSnapshot` is id, name, description, kind, externalHost,
     * group and defaultDatabaseName. There is no host, no port, no role list
     * and no health.
     *
     * Omitted rather than faked:
     *   "bastion-core-01.internal:22"  no host or port on the portal
     *                                  snapshot — deliberate on the server's
     *                                  part, the portal does not publish
     *                                  internal addresses.
     *   "ROLE oncall sre-lead"         no roles on the snapshot.
     *   Online / Unreachable, and      no health or reachability anywhere in
     *   "11 operational / 1 degraded"  the API. Same gap as the admin
     *                                  Targets screen.
     *   "RECENTLY USED" strip          no per-user usage history.
     *   "ZONE: PROD-EU-CENTRAL-1"      no zones.
     *   per-card copy button           nothing to copy; the address the
     *                                  mockup copies is the one field that
     *                                  does not exist.
     *
     * The protocol filter chips are kept — those are derived from `kind`,
     * which is real, and they are the part of the design that earns its place
     * once the list is long.
     */
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { stringifyError } from 'common/errors'
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
    import { firstBy } from 'thenby'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Menu from 'ui/Menu.svelte'
    import Modal from 'ui/Modal.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import {
        collapsedTargetGroups,
        openTargetsInNewTab,
        openTargetsInNewTabForced,
        serverInfo,
        setOpenTargetsInNewTab,
    } from '../lib/store'
    import {
        openWebDesktopSession,
        openWebSshSession,
    } from '../lib/webSessions'

    const PROTOCOL_LABELS: Record<string, string> = {
        [TargetKind.Ssh]: 'SSH',
        [TargetKind.Http]: 'HTTP',
        [TargetKind.MySql]: 'MySQL',
        [TargetKind.Postgres]: 'PostgreSQL',
        [TargetKind.Kubernetes]: 'Kubernetes',
        [TargetKind.Vnc]: 'VNC',
        [TargetKind.Rdp]: 'RDP',
    }

    let instructionsTarget: TargetSnapshot | undefined = $state()
    // The target an in-browser session is being opened for. Opening one can
    // take as long as an administrator takes to approve it, and until then
    // there is nothing else on screen to say the click did anything.
    let openingTarget: TargetSnapshot | undefined = $state()
    let openError: string | undefined = $state()
    let kindFilter: string = $state('all')
    let loadedKinds: string[] = $state([])

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

                const sorted = result.sort(
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

                // Chips reflect everything the search returned, not what the
                // chip filter then narrows it to — otherwise picking one chip
                // makes the others vanish.
                loadedKinds = [...new Set(sorted.map(t => t.kind))]

                const visible =
                    kindFilter === 'all'
                        ? sorted
                        : sorted.filter(t => t.kind === kindFilter)

                return {
                    items: visible,
                    offset: 0,
                    total: visible.length,
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
                void openInBrowser(target, () => openWebSshSession(target.id))
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

    /** The verb on the primary button, which differs by protocol. */
    function actionLabel(target: TargetSnapshot): string {
        if (target.kind === TargetKind.Http) {
            return 'Open web'
        }
        if (target.kind === TargetKind.Rdp || target.kind === TargetKind.Vnc) {
            return webClientsEnabled ? 'Launch desktop' : 'How to connect'
        }
        if (target.kind === TargetKind.Ssh) {
            return webClientsEnabled &&
                $serverInfo?.targetClickAction !==
                    TargetClickAction.ShowInstructions
                ? 'Connect'
                : 'How to connect'
        }
        return 'How to connect'
    }

    function menuGroupsFor(target: TargetSnapshot) {
        const items = []
        if (target.kind === TargetKind.Ssh && webClientsEnabled) {
            items.push({
                id: 'web-terminal',
                label: 'Web terminal',
                onselect: () =>
                    void openInBrowser(target, () =>
                        openWebSshSession(target.id),
                    ),
            })
        }
        if (
            (target.kind === TargetKind.Vnc ||
                target.kind === TargetKind.Rdp) &&
            webClientsEnabled
        ) {
            items.push({
                id: 'web-desktop',
                label: 'Web desktop',
                onselect: () => openWebDesktopSession(target.id),
            })
        }
        items.push({
            id: 'instructions',
            label: 'Connection instructions',
            onselect: () => showInstructions(target),
        })
        if (canEditTargets) {
            items.push({
                id: 'edit',
                label: 'Edit target',
                href: `/@warpgate/admin#/config/targets/${target.id}`,
            })
        }
        return [{ items }]
    }

    const kindSegments = $derived([
        { value: 'all', label: 'All' },
        ...loadedKinds.map(k => ({
            value: k,
            label: PROTOCOL_LABELS[k] ?? k,
        })),
    ])

    const preferenceGroup = $derived([
        {
            label: 'Preferences',
            items: [
                {
                    id: 'new-tab',
                    label: 'Open targets in a new tab',
                    checked: $openTargetsInNewTab,
                    disabled: $openTargetsInNewTabForced,
                    hint: $openTargetsInNewTabForced
                        ? 'Managed by the administrator'
                        : undefined,
                    onselect: () =>
                        setOpenTargetsInNewTab(!$openTargetsInNewTab),
                },
            ],
        },
    ])
</script>

<div class="head">
    <h1>My targets</h1>
    <p class="lede">Everything you can reach through Warpgate.</p>
</div>

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo?.setupState} />
{/if}

{#if openingTarget}
    <div class="notice">
        <Callout title="Connecting to {openingTarget.name}">
            If this target needs approval, it will start once an administrator
            approves it.
        </Callout>
    </div>
{/if}

{#if openError}
    <div class="notice">
        <Callout tone="danger" title="Could not open that target">
            {openError}
        </Callout>
    </div>
{/if}

{#key kindFilter}
    <ItemList
        load={loadTargets}
        showSearch={true}
        groupObject={groupInfoFromTarget}
        groupKey={group => group.id}
        bind:collapsedGroups={$collapsedTargetGroups}
    >
        {#snippet searchInput(value, setValue)}
            <div class="toolbar">
                <div class="toolbar-search">
                    <Input
                        label="Filter targets"
                        labelHidden
                        type="search"
                        size="compact"
                        placeholder="Filter targets…"
                        {value}
                        oninput={e =>
                            setValue((e.target as HTMLInputElement).value)}
                    />
                </div>
                {#if kindSegments.length > 2}
                    <SegmentedControl
                        label="Filter by protocol"
                        size="compact"
                        segments={kindSegments}
                        bind:value={kindFilter}
                    />
                {/if}
            </div>
        {/snippet}

        {#snippet header(items, groupControls)}
            {#if items?.length}
                <div class="overflow">
                    <ListOverflowMenu
                        {groupControls}
                        extraGroups={preferenceGroup}
                        label="Target list options"
                    />
                </div>
            {/if}
        {/snippet}

        {#snippet empty()}
            <EmptyState
                title={kindFilter === 'all'
                    ? "You don't have access to any targets yet"
                    : 'No targets of that kind'}
                hint={kindFilter === 'all'
                    ? 'An administrator assigns the targets you can reach.'
                    : undefined}
            />
        {/snippet}

        {#snippet groupHeader(group, state)}
            <CollapsibleGroupHeader {group} {state} />
        {/snippet}

        {#snippet container(rows)}
            <ul class="grid">
                {@render rows()}
            </ul>
        {/snippet}

        {#snippet item(target)}
            <li class="card">
                <div class="card-top">
                    <Badge mono>
                        {PROTOCOL_LABELS[target.kind] ?? target.kind}
                    </Badge>
                    <Menu
                        groups={menuGroupsFor(target)}
                        label="Actions for {target.name}"
                    />
                </div>

                <a
                    class="card-name"
                    href={urlForTarget(target)}
                    target={target.kind === TargetKind.Http &&
                    $openTargetsInNewTab
                        ? '_blank'
                        : undefined}
                    onclick={e => {
                        // Let the browser handle a modified click, so a target
                        // can still be opened in a new tab deliberately.
                        if (e.metaKey || e.ctrlKey) {
                            return
                        }
                        e.preventDefault()
                        e.stopPropagation()
                        selectTarget(target)
                    }}
                >
                    {target.name}
                </a>

                {#if target.description}
                    <p class="card-description">{target.description}</p>
                {/if}

                <div class="card-actions">
                    <Button
                        variant="primary"
                        size="compact"
                        onclick={() => selectTarget(target)}
                    >
                        {actionLabel(target)}
                    </Button>
                </div>
            </li>
        {/snippet}
    </ItemList>
{/key}

{#if $serverInfo?.setupState && !$serverInfo.setupState.hasTargets}
    <EmptyState
        title="No other targets yet"
        hint="Once you add targets and assign access, they will appear here"
    />
{/if}

<Modal
    open={!!instructionsTarget}
    title="Connect to {instructionsTarget?.name ?? ''}"
    size="lg"
    onclose={() => (instructionsTarget = undefined)}
>
    {#if instructionsTarget}
        {@const t = instructionsTarget}
        <ConnectionInstructions
            targetName={t.name}
            username={$serverInfo?.username}
            targetKind={t.kind ?? TargetKind.Ssh}
            targetDefaultDatabaseName={t.kind === TargetKind.MySql ||
            t.kind === TargetKind.Postgres
                ? t.defaultDatabaseName
                : undefined}
        />
    {/if}

    {#snippet footer()}
        {#if instructionsTarget?.kind === TargetKind.Ssh && webClientsEnabled}
            {@const sshTarget = instructionsTarget}
            <Button
                variant="primary"
                onclick={() => {
                    instructionsTarget = undefined
                    void openInBrowser(sshTarget, () =>
                        openWebSshSession(sshTarget.id),
                    )
                }}
            >
                Web terminal
            </Button>
        {/if}
        <Button onclick={() => (instructionsTarget = undefined)}>Close</Button>
    {/snippet}
</Modal>

<style>
    .head {
        margin-bottom: var(--wg-space-xl);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .lede {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .toolbar {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-md);
    }

    .toolbar-search {
        flex: 1 1 14rem;
        min-width: 0;
    }

    .overflow {
        display: flex;
        justify-content: flex-end;
        margin-bottom: var(--wg-space-sm);
    }

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr));
        gap: var(--wg-space-md);
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .card {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        min-width: 0;
    }

    .card-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-sm);
    }

    .card-name {
        font: var(--wg-text-headline-sm, var(--wg-text-body-lg));
        color: var(--wg-text);
        text-decoration: none;
        overflow-wrap: anywhere;
    }

    .card-name:hover {
        text-decoration: underline;
    }

    .card-name:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .card-description {
        margin: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
        overflow-wrap: anywhere;
    }

    .card-actions {
        display: flex;
        gap: var(--wg-space-sm);
        margin-top: var(--wg-space-md);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
