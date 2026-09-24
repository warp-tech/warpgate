<script lang="ts">
    /**
     * Issue a ticket — screen 8, sub-form.
     *
     * ── Enumeration of admin/config/CreateTicket.svelte ──────────────────
     * Loads targets and users, each sorted by name; user select; target
     * select; description; optional expiry (datetime-local); optional number
     * of uses (min 1); createTicket; handleReauthError BEFORE the generic
     * error path; the show-once secret via ConnectionInstructions with its
     * externalHost and defaultDatabaseName plumbing; a Done link back to the
     * list.
     *
     * ── handleReauthError is load-bearing ────────────────────────────────
     * Issuing a ticket is a privileged action behind step-up auth. The server
     * answers with a re-auth challenge, and handleReauthError redirects to it.
     * Treating that as an ordinary failure would show "403" and strand the
     * admin on a form whose contents are about to be discarded, so it stays
     * ahead of stringifyError exactly as it was.
     *
     * ── Still delegating: ConnectionInstructions ─────────────────────────
     * 529 lines, sveltestrap-based, shared by six callers including the
     * already-migrated target detail screen. It migrates as its own unit at
     * screen 13, where it is most central — the same treatment the credential
     * modals got in 6c rather than being absorbed piecemeal here.
     *
     * ── Selects hold ids, not objects ────────────────────────────────────
     * The original bound `<option value={user}>` to whole objects, which works
     * only because Svelte keeps a reference map; it breaks the moment the list
     * reloads and the objects are new. ui/Select is a real <select> over
     * strings, so these bind ids and look the record up.
     */
    import {
        api,
        type Target,
        type TicketAndSecret,
        type User,
    } from 'admin/lib/api'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { stringifyError } from 'common/errors'
    import 'ui/layout.css'
    import { handleReauthError } from 'common/reauth'
    import { TargetKind } from 'gateway/lib/api'
    import { link } from 'svelte-spa-router'
    import { firstBy } from 'thenby'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import Spinner from 'ui/Spinner.svelte'

    let error: string | undefined = $state()
    let targets: Target[] | undefined = $state()
    let users: User[] | undefined = $state()
    let selectedTargetId = $state('')
    let selectedUserId = $state('')
    let expiry = $state('')
    let numberOfUses: string = $state('')
    let description = $state('')
    let result: TicketAndSecret | undefined = $state()

    const selectedTarget = $derived(
        targets?.find(t => t.id === selectedTargetId),
    )
    const selectedUser = $derived(users?.find(u => u.id === selectedUserId))

    async function load() {
        const [t, u] = await Promise.all([api.getTargets(), api.getUsers()])
        targets = t.sort(firstBy('name'))
        users = u.sort(firstBy('username'))
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    async function create() {
        if (!selectedTarget || !selectedUser) {
            return
        }
        try {
            result = await api.createTicket({
                createTicketRequest: {
                    userId: selectedUser.id,
                    targetId: selectedTarget.id,
                    expiry: expiry ? new Date(expiry) : undefined,
                    numberOfUses: numberOfUses
                        ? Number(numberOfUses)
                        : undefined,
                    description,
                },
            })
            error = undefined
        } catch (err) {
            // Step-up auth first: this is a redirect, not a failure.
            if (await handleReauthError(err)) {
                return
            }
            error = await stringifyError(err)
        }
    }

    const targetOptions = $derived(
        (targets ?? []).map(t => ({ value: t.id, label: t.name })),
    )
    const userOptions = $derived(
        (users ?? []).map(u => ({ value: u.id, label: u.username })),
    )
    const ready = $derived(!!selectedTarget && !!selectedUser)
</script>

<div class="page">
    {#if result}
        <h1>Ticket issued</h1>

        <Callout tone="warning" title="The secret is shown once">
            Copy it now. Warpgate stores only a hash, so this value cannot be
            shown again — if it is lost, delete the ticket and issue another.
        </Callout>

        {#if selectedTarget && selectedUser}
            {@const t = selectedTarget}
            <div class="instructions">
                <ConnectionInstructions
                    targetName={t.name}
                    targetKind={t.options.kind}
                    username={selectedUser.username}
                    targetExternalHost={t.options.kind === TargetKind.Http
                        ? t.options.externalHost
                        : undefined}
                    ticketSecret={result.secret}
                    targetDefaultDatabaseName={t.options.kind ===
                        TargetKind.MySql || t.options.kind === TargetKind.Postgres
                        ? t.options.defaultDatabaseName
                        : undefined}
                />
            </div>
        {/if}

        <a class="done" href="/config/tickets" use:link>Done</a>
    {:else}
        <h1>Issue an access ticket</h1>
        <p class="lede">
            A ticket lets one user reach one target without any further
            authentication. It stops working at its expiry or when its uses run
            out, whichever comes first.
        </p>

        {#if error}
            <Callout tone="danger" title="Could not issue the ticket">
                {error}
            </Callout>
        {/if}

        {#if !targets || !users}
            <Spinner label="Loading targets and users" />
        {:else}
            <div class="wg-field-stack">
                <Select
                    label="Authorise as user"
                    required
                    options={userOptions}
                    placeholder="Choose a user…"
                    bind:value={selectedUserId}
                    hint="The ticket connects as this user, with their roles."
                />

                <Select
                    label="Target"
                    required
                    options={targetOptions}
                    placeholder="Choose a target…"
                    bind:value={selectedTargetId}
                />

                <Input
                    label="Description"
                    placeholder="What is this ticket for?"
                    bind:value={description}
                    hint="Shown in the ticket list. Optional, but the list is hard to audit without it."
                />

                <Input
                    label="Expires"
                    type="datetime-local"
                    bind:value={expiry}
                    hint="Optional. Leave blank for a ticket that never expires on time alone."
                />

                <Input
                    label="Number of uses"
                    type="number"
                    inputmode="numeric"
                    min="1"
                    bind:value={numberOfUses}
                    hint="Optional. Leave blank for unlimited uses."
                />

                <div class="actions">
                    <a class="cancel" href="/config/tickets" use:link>Cancel</a>
                    <Button variant="primary" disabled={!ready} click={create}>
                        Issue ticket
                    </Button>
                </div>
            </div>
        {/if}
    {/if}
</div>

<style>
    .page {
        max-width: 42rem;
    }

    h1 {
        margin: 0 0 var(--wg-space-xs);
        font: var(--wg-text-headline-lg);
    }

    .lede {
        margin: 0 0 var(--wg-space-xl);
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .instructions {
        margin: var(--wg-space-xl) 0;
    }

    .actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-md);
    }

    .cancel,
    .done {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .done {
        display: inline-block;
        margin-top: var(--wg-space-lg);
    }

    .cancel:focus-visible,
    .done:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
