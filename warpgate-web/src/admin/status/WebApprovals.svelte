<script lang="ts">
    import { Alert, Button, Input } from '@sveltestrap/sveltestrap'
    import { api, type ActiveWebApprovalInfo } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { onMount } from 'svelte'

    let loading = $state(true)
    let error: string | undefined = $state()
    let approvals: ActiveWebApprovalInfo[] | undefined = $state()
    let usernameToClear = $state('')

    let usersWithActiveCache = $derived(
        [...new Set((approvals ?? []).map(a => a.username))].sort(),
    )

    async function load() {
        loading = true
        error = undefined
        try {
            approvals = await api.listWebApprovals()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    load()

    $effect(() => {
        if (usernameToClear && !usersWithActiveCache.includes(usernameToClear)) {
            usernameToClear = ''
        }
    })

    onMount(() => {
        const refreshTimer = setInterval(load, 30_000)
        return () => {
            clearInterval(refreshTimer)
        }
    })

    async function clearAll() {
        if (
            !confirm(
                'Clear every cached approval bypass? Everyone currently relying on one will be asked to approve again on their next connection.',
            )
        ) {
            return
        }
        try {
            await api.clearWebApprovals()
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function clearForUser(username: string) {
        if (
            !confirm(
                `Clear cached approval bypasses for ${username}? They'll be asked to approve again on their next connection.`,
            )
        ) {
            return
        }
        try {
            await api.clearWebApprovalsForUser({ username })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function clearForSelectedUser() {
        if (!usernameToClear) {
            return
        }
        await clearForUser(usernameToClear)
        usernameToClear = ''
    }

    function scopeDescription(approval: ActiveWebApprovalInfo) {
        return approval.allTargets ? 'all targets' : `target "${approval.scope}"`
    }

    async function revokeApproval(approval: ActiveWebApprovalInfo) {
        if (
            !confirm(
                `Revoke ${approval.username}'s cached approval for ${scopeDescription(approval)}? They'll be asked to approve again on their next connection to it.`,
            )
        ) {
            return
        }
        try {
            await api.clearWebApprovalScopeForUser({
                username: approval.username,
                target: approval.scopeTarget,
                allTargets: approval.allTargets,
            })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>web approvals</h1>
        <AsyncButton color="danger" outline click={clearAll}>
            Clear all
        </AsyncButton>
    </div>

    <p class="text-muted">
        Cached approval bypasses let a previously-approved login skip
        re-approval for a while. Clear them here to force re-approval
        immediately &mdash; for example during offboarding or after a
        suspected key compromise.
    </p>

    {#if error}
        <Alert color="danger" dismissible onclose={() => { error = undefined }}>
            {error}
            <Button color="link" size="sm" onclick={load}>Retry</Button>
        </Alert>
    {/if}

    <div class="d-flex gap-2 mb-3">
        <Input type="select" bind:value={usernameToClear} disabled={usersWithActiveCache.length === 0}>
            <option value="">
                {usersWithActiveCache.length > 0 ? 'Select a user…' : 'No users with an active cache'}
            </option>
            {#each usersWithActiveCache as username (username)}
                <option value={username}>{username}</option>
            {/each}
        </Input>
        <AsyncButton
            color="secondary"
            outline
            disabled={!usernameToClear}
            click={clearForSelectedUser}
        >
            Clear all for user
        </AsyncButton>
    </div>

    {#if loading && !approvals}
        <DelayedSpinner />
    {:else if approvals && approvals.length > 0}
        <div class="section-header">
            <h5 class="m-0">Active approvals</h5>
            <span class="badge text-bg-secondary">{approvals.length}</span>
        </div>
        <div class="list-group list-group-flush mb-3">
            {#each approvals as approval (`${approval.username}-${approval.remoteIp}-${approval.protocol}-${approval.scope}`)}
                <div class="list-group-item">
                    <div class="d-flex align-items-center w-100">
                        <div>
                            <strong>{approval.username}</strong>
                            <small class="d-block text-muted">
                                {approval.protocol}
                                &middot; {approval.scope}
                                &middot; from {approval.remoteIp}
                                &middot; approved
                                <RelativeDate
                                    date={new Date(approval.grantedAt)}
                                />
                            </small>
                        </div>
                        <AsyncButton
                            class="ms-auto"
                            color="link"
                            click={() => revokeApproval(approval)}
                        >
                            Revoke
                        </AsyncButton>
                    </div>
                </div>
            {/each}
        </div>
    {:else}
        <p class="text-muted">No active approval bypasses.</p>
    {/if}
</div>

<style lang="scss">
    .section-header {
        display: flex;
        align-items: center;
        gap: .5rem;
        margin-bottom: .5rem;
    }
</style>
