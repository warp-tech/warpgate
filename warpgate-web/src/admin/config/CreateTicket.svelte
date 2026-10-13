<script lang="ts">
    import { Alert, FormGroup } from '@sveltestrap/sveltestrap'
    import {
        api,
        type Target,
        type TicketAndSecret,
        type User,
    } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { stringifyError } from 'common/errors'
    import { handleReauthError } from 'common/reauth'
    import SearchSelect from 'common/SearchSelect.svelte'
    import { TargetKind } from 'gateway/lib/api'
    import { link } from 'svelte-spa-router'
    import { firstBy } from 'thenby'

    let error: string | null = $state(null)
    let users: User[] | undefined = $state()
    let selectedTarget: Target | undefined = $state()
    let selectedUser: User | undefined = $state()
    let selectedExpiry: string | undefined = $state()
    let selectedNumberOfUses: number | undefined = $state()
    let result: TicketAndSecret | undefined = $state()
    let selectedDescription: string = $state('')

    async function load() {
        users = await api.getUsers()
        users.sort(firstBy('username'))
    }

    function searchTargets(search: string) {
        return api.getTargetsPage({ search, limit: 50 })
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
                    expiry: selectedExpiry
                        ? new Date(selectedExpiry)
                        : undefined,
                    numberOfUses: selectedNumberOfUses,
                    description: selectedDescription,
                },
            })
        } catch (err) {
            if (await handleReauthError(err)) {
                return
            }
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    {#if result}
        <div class="page-summary-bar">
            <h1>ticket created</h1>
        </div>

        <Alert color="warning" fade={false} class="mb-3">
            The secret is only shown once - you won't be able to see it again.
        </Alert>

        {#if selectedTarget && selectedUser}
            <ConnectionInstructions
                targetName={selectedTarget.name}
                targetKind={selectedTarget.options.kind}
                username={selectedUser.username}
                targetExternalHost={selectedTarget.options.kind === 'Http' ? selectedTarget.options.externalHost : undefined}
                ticketSecret={result.secret}
                targetDefaultDatabaseName={(selectedTarget.options.kind === TargetKind.MySql || selectedTarget.options.kind === TargetKind.Postgres)
                    ? selectedTarget.options.defaultDatabaseName : undefined}
            />
        {/if}

        <a class="btn btn-secondary" href="/config/tickets" use:link>Done</a>
    {:else}
        <div class="narrow-page">
            <div class="page-summary-bar">
                <h1>create an access ticket</h1>
            </div>

            {#if users}
                <FormGroup floating label="Authorize as user">
                    <select bind:value={selectedUser} class="form-control">
                        {#each users as user (user.id)}
                            <option value={user}>
                                {user.username}
                            </option>
                        {/each}
                    </select>
                </FormGroup>
            {/if}

            <FormGroup floating label="Target">
                <SearchSelect
                    bind:value={selectedTarget}
                    load={searchTargets}
                    itemLabel={target => target.name}
                    itemKey={target => target.id}
                    placeholder="Search targets"
                />
            </FormGroup>

            <FormGroup floating label="Description">
                <input
                    type="text"
                    bind:value={selectedDescription}
                    class="form-control"
                    placeholder="Optional description"
                >
            </FormGroup>

            <FormGroup floating label="Expiry (optional)">
                <input
                    type="datetime-local"
                    bind:value={selectedExpiry}
                    class="form-control"
                >
            </FormGroup>

            <FormGroup floating label="Number of uses (optional)">
                <input
                    type="number"
                    min="1"
                    bind:value={selectedNumberOfUses}
                    class="form-control"
                >
            </FormGroup>

            <AsyncButton color="primary" click={create}>
                Create ticket
            </AsyncButton>
        </div>
    {/if}
</div>
