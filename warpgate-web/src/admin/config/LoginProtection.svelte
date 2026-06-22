<script lang="ts">
    import { api, type SecurityStatus, type BlockedIpInfo, type LockedUserInfo } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { Button } from '@sveltestrap/sveltestrap'
    import RelativeDate from '../RelativeDate.svelte'

    let loading = $state(true)
    let error: string | undefined = $state()
    let status: SecurityStatus | undefined = $state()
    let blockedIps: BlockedIpInfo[] | undefined = $state()
    let lockedUsers: LockedUserInfo[] | undefined = $state()
    let actionInFlight = $state(false)

    // Auto-refresh every 30s while the page is open.
    let refreshTimer: ReturnType<typeof setInterval> | undefined

    async function load() {
        loading = true
        error = undefined
        try {
            const [statusRes, ipsRes, usersRes] = await Promise.all([
                api.getSecurityStatus(),
                api.listBlockedIps(),
                api.listLockedUsers(),
            ])
            status = statusRes
            blockedIps = ipsRes
            lockedUsers = usersRes
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            loading = false
        }
    }

    load()
    refreshTimer = setInterval(load, 30_000)

    // Clean up interval when component is destroyed.
    import { onDestroy } from 'svelte'
    onDestroy(() => clearInterval(refreshTimer))

    async function unblockIp(ip: string) {
        if (!confirm(`Unblock ${ip}? This allows new login attempts from this address.`)) return
        actionInFlight = true
        try {
            await api.unblockIp({ ip })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            actionInFlight = false
        }
    }

    async function unlockUser(username: string) {
        if (!confirm(`Unlock ${username}? This allows the account to log in immediately.`)) return
        actionInFlight = true
        try {
            await api.unlockUser({ username })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            actionInFlight = false
        }
    }
</script>

<div class="page-summary-bar">
    <h1>Login Protection</h1>
    <Button color="secondary" size="sm" disabled={loading || actionInFlight} onclick={load}>
        {loading ? 'Refreshing…' : 'Refresh'}
    </Button>
</div>

{#if error}
    <Alert color="danger" dismissible onclose={() => { error = undefined }}>
        {error}
        <Button color="link" size="sm" onclick={load}>Retry</Button>
    </Alert>
{/if}

{#if loading && !status}
    <DelayedSpinner />
{:else}
    {#if status}
        <div class="stats-row">
            <div class="stat-card" class:text-danger={status.blockedIpCount > 0}>
                <div class="stat-value">{status.blockedIpCount}</div>
                <div class="stat-label">blocked IPs</div>
            </div>
            <div class="stat-card" class:text-warning={status.lockedUserCount > 0}>
                <div class="stat-value">{status.lockedUserCount}</div>
                <div class="stat-label">locked users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{status.failedAttemptsLastHour}</div>
                <div class="stat-label">failed attempts (1h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{status.failedAttemptsLast24h}</div>
                <div class="stat-label">failed attempts (24h)</div>
            </div>
        </div>
    {/if}

    {#if blockedIps !== undefined}
        <div class="section-header">
            <span class="section-title">Blocked IPs</span>
            {#if blockedIps.length > 0}
                <span class="badge text-bg-danger">{blockedIps.length}</span>
            {:else}
                <span class="text-muted section-empty">none</span>
            {/if}
        </div>
        {#if blockedIps.length > 0}
        <div class="list-group list-group-flush mb-3">
            {#each blockedIps as ip (ip.ipAddress)}
                <div class="list-group-item">
                    <div class="d-flex align-items-center w-100">
                        <div>
                            <strong>{ip.ipAddress}</strong>
                            <small class="d-block text-muted">
                                Block #{ip.blockCount} &middot; expires <RelativeDate date={new Date(ip.expiresAt)} />
                            </small>
                        </div>
                        <Button class="ms-auto" color="link" disabled={actionInFlight} onclick={() => unblockIp(ip.ipAddress)}>Unblock</Button>
                    </div>
                </div>
            {/each}
        </div>
        {/if}
    {/if}

    {#if lockedUsers !== undefined}
        <div class="section-header">
            <span class="section-title">Locked Users</span>
            {#if lockedUsers.length > 0}
                <span class="badge text-bg-warning">{lockedUsers.length}</span>
            {:else}
                <span class="text-muted section-empty">none</span>
            {/if}
        </div>
        {#if lockedUsers.length > 0}
        <div class="list-group list-group-flush mb-3">
            {#each lockedUsers as user (user.username)}
                <div class="list-group-item">
                    <div class="d-flex align-items-center w-100">
                        <div>
                            <strong>{user.username}</strong>
                            <small class="d-block text-muted">
                                {#if user.expiresAt}
                                    expires <RelativeDate date={new Date(user.expiresAt)} />
                                {:else}
                                    manual unlock required
                                {/if}
                            </small>
                        </div>
                        <Button class="ms-auto" color="link" disabled={actionInFlight} onclick={() => unlockUser(user.username)}>Unlock</Button>
                    </div>
                </div>
            {/each}
        </div>
        {/if}
    {/if}
{/if}

<style lang="scss">
    .stats-row {
        display: flex;
        gap: 1rem;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
    }

    .stat-card {
        flex: 1;
        min-width: 120px;
        padding: 1rem;
        background: var(--bs-body-bg);
        border: 1px solid var(--bs-border-color);
        border-radius: 0.5rem;
        text-align: center;
    }

    .stat-value {
        font-size: 1.75rem;
        font-weight: bold;
        line-height: 1;
    }

    .stat-label {
        font-size: 0.75rem;
        color: var(--bs-secondary);
        margin-top: 0.25rem;
    }

    .section-header {
        display: flex;
        align-items: center;
        gap: .5rem;
        margin-bottom: .5rem;
    }

    .section-title {
        font-weight: 600;
        font-size: .95rem;
    }

    .section-empty {
        font-size: .85rem;
    }
</style>
