<script lang="ts">
    import { api, type SecurityStatus, type BlockedIpInfo, type LockedUserInfo } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import { Button } from '@sveltestrap/sveltestrap'
    import RelativeDate from '../RelativeDate.svelte'

    let error: string | undefined = $state()
    let status: SecurityStatus | undefined = $state()
    let blockedIps: BlockedIpInfo[] | undefined = $state()
    let lockedUsers: LockedUserInfo[] | undefined = $state()

    async function load() {
        const [statusRes, ipsRes, usersRes] = await Promise.all([
            api.getSecurityStatus(),
            api.listBlockedIps(),
            api.listLockedUsers(),
        ])
        status = statusRes
        blockedIps = ipsRes
        lockedUsers = usersRes
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    async function unblockIp(ip: string) {
        await api.unblockIp({ ip })
        load()
    }

    async function unlockUser(username: string) {
        await api.unlockUser({ username })
        load()
    }
</script>

<div class="page-summary-bar">
    <h1>login protection</h1>
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

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

{#if blockedIps}
    {#if blockedIps.length}
        <h2>Blocked IPs: {blockedIps.length}</h2>
    {:else}
        <h2>No blocked IPs</h2>
    {/if}
    <div class="list-group list-group-flush">
        {#each blockedIps as ip (ip.ipAddress)}
            <div class="list-group-item">
                <div class="d-flex align-items-center w-100">
                    <div>
                        <strong>{ip.ipAddress}</strong>
                        <small class="d-block text-muted">
                            Block #{ip.blockCount} &middot; expires <RelativeDate date={new Date(ip.expiresAt)} />
                        </small>
                    </div>
                    <Button class="ms-auto" color="link" onclick={e => {
                        e.preventDefault()
                        unblockIp(ip.ipAddress)
                    }}>Unblock</Button>
                </div>
            </div>
        {/each}
    </div>
{/if}

<div class="mb-3"></div>

{#if lockedUsers}
    {#if lockedUsers.length}
        <h2>Locked users: {lockedUsers.length}</h2>
    {:else}
        <h2>No locked users</h2>
    {/if}
    <div class="list-group list-group-flush">
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
                    <Button class="ms-auto" color="link" onclick={e => {
                        e.preventDefault()
                        unlockUser(user.username)
                    }}>Unlock</Button>
                </div>
            </div>
        {/each}
    </div>
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
</style>
