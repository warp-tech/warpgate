<script lang="ts">
    /**
     * Target detail — screen 4a: page shell, common fields, save bar,
     * ConfirmDialog migration.
     *
     * All six protocols now delegate to migrated components under
     * ./ssh, ./http, ./rdp, ./vnc, ./database and ./kubernetes (4b–4f).
     *
     * PAGE, NOT DRAWER — divergence 6, by decision. warpgate_add_target_drawer
     * draws this as a 560px drawer. Two reasons it stays a page: a
     * protocol-dependent form this size is cramped at 560px, and a drawer is
     * not linkable, so an admin cannot send a colleague a URL to a target's
     * configuration. The drawer's *content* design is applied — section
     * divisions, helper text under its field, and no "Test connection", which
     * has no probe endpoint behind it.
     *
     * Behaviour preserved from config/targets/Target.svelte:
     *   - the access-instructions modal, re-keyed on open so examples
     *     regenerate, with the user picker for protocols that take a username
     *   - "Connect" opens a web SSH or desktop session, gated on
     *     webClientsEnabled and the three protocols that support it
     *   - role toggles write through immediately; the rest of the form saves
     *     on "Update configuration"
     *   - the access-control and self-service switches save on change, which
     *     is why they stay switches rather than becoming checkboxes
     *
     * window.confirm for deletion is replaced by a TYPED ConfirmDialog: a
     * target is a config object with dependents and audit relationships, and
     * its blast radius is not visible from the dialog.
     */
    import {
        api,
        type Role,
        type Target,
        type TargetGroup,
    } from 'admin/lib/api'
    import Section from 'admin/lib/Section.svelte'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import { adminPermissions } from 'admin/lib/store'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { humantimeDuration } from 'common/duration'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import { serverInfo } from 'gateway/lib/store'
    import {
        openWebDesktopSession,
        openWebSshSession,
    } from 'gateway/lib/webSessions'
    import { replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import TargetDatabaseOptions from './database/Options.svelte'
    import TargetHttpOptions from './http/Options.svelte'
    import TargetKubernetesOptions from './kubernetes/Options.svelte'
    import ProtocolDocs from './ProtocolDocs.svelte'
    import TargetRdpOptions from './rdp/Options.svelte'
    import TargetSshOptions from './ssh/Options.svelte'
    import TargetVncOptions from './vnc/Options.svelte'

    interface Props {
        params: { id: string }
    }

    const { params }: Props = $props()

    const PROTOCOL_LABELS: Record<string, string> = {
        [TargetKind.Http]: 'HTTP target',
        [TargetKind.MySql]: 'MySQL target',
        [TargetKind.Postgres]: 'PostgreSQL target',
        [TargetKind.Ssh]: 'SSH target',
        [TargetKind.Kubernetes]: 'Kubernetes target',
        [TargetKind.Vnc]: 'VNC target',
        [TargetKind.Rdp]: 'RDP target',
    }

    let error: string | undefined = $state()
    let selectedUsername: string | undefined = $state($serverInfo?.username)
    let target: Target | undefined = $state()
    let roleIsAllowed: Record<string, boolean> = $state({})
    let instructionsOpen = $state(false)
    let deleteOpen = $state(false)
    let groups: TargetGroup[] = $state([])

    async function init() {
        ;[target, groups] = await Promise.all([
            api.getTarget({ id: params.id }),
            api.listTargetGroups(),
        ])
        return target
    }

    async function loadRoles() {
        if (!target) {
            return []
        }
        const allRoles = await api.getRoles()
        const allowedRoles = await api.getTargetRoles(target)
        roleIsAllowed = Object.fromEntries(allowedRoles.map(r => [r.id, true]))
        return allRoles
    }

    async function update() {
        if (!target) {
            return
        }
        try {
            if (target.options.kind === 'Http') {
                target.options.externalHost =
                    target.options.externalHost || undefined
            }
            target = await api.updateTarget({
                id: params.id,
                targetDataRequest: target,
            })
            toast.success('Target saved')
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove() {
        if (!target) {
            return
        }
        await api.deleteTarget(target)
        replace('/config/targets')
    }

    async function connect() {
        if (!target) {
            return
        }
        try {
            if (target.options.kind === 'Ssh') {
                await openWebSshSession(target.id)
            } else {
                await openWebDesktopSession(target.id)
            }
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function toggleRole(role: Role) {
        if (!target) {
            return
        }
        if (roleIsAllowed[role.id]) {
            await api.deleteTargetRole({ id: target.id, roleId: role.id })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
        } else {
            await api.addTargetRole({ id: target.id, roleId: role.id })
            roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
        }
    }

    const PG_PROTOCOL_VERSIONS = [
        { value: '3.2', label: '3.2' },
        { value: '3.0', label: '3.0' },
    ]

    const groupOptions = $derived([
        { value: '', label: 'No group' },
        ...groups.map(g => ({ value: g.id, label: g.name })),
    ])

    const canUseWebClient = $derived.by(() => {
        const t = target
        if (!t || !($serverInfo?.webClientsEnabled ?? true)) {
            return false
        }
        return (
            t.options.kind === 'Ssh' ||
            t.options.kind === 'Rdp' ||
            t.options.kind === 'Vnc'
        )
    })

    const needsUsernameForInstructions = $derived.by(() => {
        const k = target?.options.kind
        return (
            k === 'Ssh' ||
            k === 'MySql' ||
            k === 'Postgres' ||
            k === 'Kubernetes'
        )
    })
</script>

<Loadable promise={init()} bind:value={target}>
    {#snippet children(target)}
        <div class="head">
            <div>
                <h1>{target.name}</h1>
                <p class="subtitle">
                    {PROTOCOL_LABELS[target.options.kind] ?? target.options.kind}
                </p>
            </div>
        </div>

        <div class="layout">
            <div class="form-column">
                <SectionedForm>
                    <Section id="general" title="General">
                        <div class="grid">
                            <Input label="Name" bind:value={target.name} />
                            {#if groups.length > 0}
                                <Select
                                    label="Group"
                                    options={groupOptions}
                                    value={target.groupId ?? ''}
                                    onchange={e => {
                                        const v = (e.target as HTMLSelectElement)
                                            .value
                                        target.groupId = v || undefined
                                    }}
                                />
                            {/if}
                        </div>
                        <Input
                            label="Description"
                            bind:value={target.description}
                            hint="Shown to users in the portal target list."
                        />
                    </Section>

                    <!-- 4b–4f replace the contents of this section, one
                         protocol at a time. -->
                    <Section id="target-options" title="Target options">
                        {#if target.options.kind === 'Ssh'}
                            <TargetSshOptions
                                id={target.id}
                                options={target.options}
                            />
                        {:else if target.options.kind === 'Vnc'}
                            <TargetVncOptions bind:options={target.options} />
                        {:else if target.options.kind === 'Rdp'}
                            <TargetRdpOptions bind:options={target.options} />
                        {:else if target.options.kind === 'Http'}
                            <TargetHttpOptions bind:options={target.options} />
                        {:else if target.options.kind === 'MySql' || target.options.kind === 'Postgres'}
                            <TargetDatabaseOptions
                                bind:options={target.options}
                            />
                        {:else if target.options.kind === 'Kubernetes'}
                            <TargetKubernetesOptions
                                bind:options={target.options}
                            />
                        {/if}
                    </Section>

                    <Section
                        id="roles"
                        title="Roles"
                        bodyTitle="Allow access for roles"
                    >
                        <Loadable promise={loadRoles()}>
                            {#snippet children(roles)}
                                <ul class="role-list">
                                    {#each roles as role (role.id)}
                                        <li>
                                            <Toggle
                                                label={role.name}
                                                hint={role.description ||
                                                    undefined}
                                                checked={roleIsAllowed[role.id]}
                                                disabled={!$adminPermissions.targetsEdit}
                                                onchange={() => toggleRole(role)}
                                            />
                                        </li>
                                    {/each}
                                </ul>
                            {/snippet}
                        </Loadable>
                    </Section>

                    <Section id="network" title="Network">
                        <label
                            class="field-label"
                            for="rateLimitBytesPerSecond"
                        >
                            Global bandwidth limit
                        </label>
                        <RateLimitInput
                            id="rateLimitBytesPerSecond"
                            bind:value={target.rateLimitBytesPerSecond}
                        />
                    </Section>

                    <!--
                      Restored in 4f. These three fields were dropped when 4a
                      rewrote the page shell; they are Postgres/MySQL-only and
                      live outside the protocol options component because the
                      original kept them in their own section.
                    -->
                    {#if target.options.kind === 'MySql' || target.options.kind === 'Postgres'}
                        <Section id="advanced" title="Advanced">
                            {#if target.options.kind === 'Postgres'}
                                <Select
                                    label="Protocol version"
                                    options={PG_PROTOCOL_VERSIONS}
                                    bind:value={target.options.protocolVersion}
                                    hint="Some non-compliant Postgres proxies do not implement automatic version negotiation and need 3.0."
                                />

                                <Input
                                    label="Idle timeout"
                                    placeholder="10m"
                                    bind:value={target.options.idleTimeout}
                                    hint="How long an authenticated session can idle before re-authenticating. Examples: 30m, 1h, 2h30m. Empty uses the default of 10m."
                                />
                            {/if}

                            <Input
                                label="Default database name for connection examples"
                                mono
                                placeholder="database-name"
                                bind:value={target.options.defaultDatabaseName}
                                hint="Display only — it does not restrict which databases users can reach. Empty uses the global default."
                            />
                        </Section>
                    {/if}

                    <Section id="access-control" title="Access control">
                        <!-- Writes through on change, so a switch is honest here -->
                        <Toggle
                            label="Require administrator approval for each connection"
                            checked={target.requireApproval}
                            hint="Sessions are held after authentication — including ticket connections — until an administrator approves them. HTTP and Kubernetes requests are refused with a retryable response until then."
                            onchange={() => {
                                target.requireApproval = !target.requireApproval
                                update()
                            }}
                        />
                    </Section>

                    {#if $serverInfo?.ticketSelfServiceEnabled}
                        <Section
                            id="self-service-tickets"
                            title="Self-service tickets"
                        >
                            <Toggle
                                label="Disable ticket requests for this target"
                                checked={target.ticketRequestsDisabled}
                                onchange={() => {
                                    target.ticketRequestsDisabled =
                                        !target.ticketRequestsDisabled
                                    update()
                                }}
                            />
                            <Toggle
                                label="Always require admin approval"
                                checked={target.ticketRequireApproval}
                                onchange={() => {
                                    target.ticketRequireApproval =
                                        !target.ticketRequireApproval
                                    update()
                                }}
                            />
                            <div class="field">
                                <label
                                    class="field-label"
                                    for="ticketMaxDuration"
                                >
                                    Max self-service ticket duration
                                </label>
                                <input
                                    id="ticketMaxDuration"
                                    class="raw-input"
                                    type="text"
                                    placeholder="Use global default"
                                    use:humantimeDuration={{
                                        seconds: target.ticketMaxDurationSeconds,
                                        onChange: v => {
                                            target.ticketMaxDurationSeconds = v
                                            update()
                                        },
                                    }}
                                >
                                <p class="field-hint">
                                    Examples: 30m, 8h, 1d. Leave empty to use
                                    the global default.
                                </p>
                            </div>

                            <Input
                                label="Max uses per ticket"
                                type="number"
                                value={target.ticketMaxUses?.toString() ?? ''}
                                hint="Leave empty to use the global default."
                                oninput={e => {
                                    const v = Number.parseInt(
                                        (e.target as HTMLInputElement).value,
                                        10,
                                    )
                                    target.ticketMaxUses = Number.isNaN(v)
                                        ? undefined
                                        : v
                                    update()
                                }}
                            />
                        </Section>
                    {/if}
                </SectionedForm>
            </div>

            <aside class="docs-column">
                <ProtocolDocs kind={target.options.kind} />
            </aside>
        </div>

        {#if error}
            <Callout tone="danger" title="Something went wrong"
                >{error}</Callout
            >
        {/if}

        <div class="action-bar">
            <div class="action-bar-start">
                {#if canUseWebClient}
                    <Button click={connect}>Connect</Button>
                {/if}
                <Button onclick={() => (instructionsOpen = true)}>
                    Access instructions
                </Button>
            </div>
            <Button
                variant="primary"
                click={update}
                disabled={!$adminPermissions.targetsEdit}
            >
                Update configuration
            </Button>
            <Button
                variant="destructive"
                disabled={!$adminPermissions.targetsDelete}
                onclick={() => (deleteOpen = true)}
            >
                Remove
            </Button>
        </div>

        <Modal
            bind:open={instructionsOpen}
            title="Access instructions"
            size="lg"
        >
            {#if needsUsernameForInstructions}
                <Loadable promise={api.getUsers()}>
                    {#snippet children(users)}
                        <Select
                            label="Select a user"
                            options={users.map(u => ({
                                value: u.username,
                                label: u.username,
                            }))}
                            bind:value={selectedUsername}
                        />
                    {/snippet}
                </Loadable>
            {/if}

            <!-- Re-keyed so the examples regenerate when the modal opens -->
            {#key instructionsOpen}
                <ConnectionInstructions
                    targetName={target.name}
                    username={selectedUsername}
                    targetKind={target.options.kind}
                    targetExternalHost={target.options.kind === TargetKind.Http
                        ? target.options.externalHost
                        : undefined}
                    targetDefaultDatabaseName={target.options.kind ===
                        TargetKind.MySql ||
                    target.options.kind === TargetKind.Postgres
                        ? target.options.defaultDatabaseName
                        : undefined}
                />
            {/key}

            {#snippet footer()}
                <Button onclick={() => (instructionsOpen = false)}
                    >Close</Button
                >
            {/snippet}
        </Modal>

        <ConfirmDialog
            bind:open={deleteOpen}
            title="Delete {target.name}?"
            confirmLabel="Delete target"
            confirmText={target.name}
            confirmTextLabel="target name"
            onconfirm={remove}
        >
            <p>
                Deleting this target removes it from every role that grants
                access to it, and from the connection history shown against past
                sessions. This cannot be undone.
            </p>
        </ConfirmDialog>
    {/snippet}
</Loadable>

<style>
    .head {
        margin-bottom: var(--wg-space-xl);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .subtitle {
        margin: var(--wg-space-xs) 0 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .layout {
        display: flex;
        gap: var(--wg-space-2xl);
        align-items: flex-start;
    }

    .form-column {
        flex: 1 1 auto;
        min-width: 0;
        max-width: 48rem;
    }

    .docs-column {
        flex: none;
        width: 15rem;
    }

    .grid {
        display: grid;
        grid-template-columns: 2fr 1fr;
        gap: var(--wg-space-lg);
        margin-bottom: var(--wg-space-lg);
    }

    .role-list {
        list-style: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
    }

    .field {
        margin-bottom: var(--wg-space-lg);
    }

    .field-label {
        display: block;
        margin-bottom: var(--wg-space-xs);
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .field-hint {
        margin: var(--wg-space-xs) 0 0;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    /* The duration field is driven by the humantimeDuration action, which
     * needs the raw element rather than the Input component. */
    .raw-input {
        width: 100%;
        height: var(--wg-control-height);
        padding: 0 var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    .raw-input:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-color: var(--wg-primary);
    }

    .action-bar {
        position: sticky;
        bottom: 0;
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-top: var(--wg-space-xl);
        padding: var(--wg-space-md) 0;
        background: var(--wg-surface);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    .action-bar-start {
        display: flex;
        gap: var(--wg-space-sm);
        margin-right: auto;
    }

    @media (max-width: 900px) {
        .layout {
            flex-direction: column;
        }

        .docs-column {
            width: 100%;
        }

        .grid {
            grid-template-columns: 1fr;
        }
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }

        .action-bar {
            flex-wrap: wrap;
        }
    }
</style>
