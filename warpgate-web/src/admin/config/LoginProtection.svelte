<script lang="ts">
    import { api, type SecurityStatus, type BlockedIpInfo, type LockedUserInfo } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { Button } from '@sveltestrap/sveltestrap'
    import RelativeDate from '../RelativeDate.svelte'
    import { onMount } from 'svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import StatCard from 'common/StatCard.svelte'

    let loading = $state(true)
    let error: string | undefined = $state()
    let status: SecurityStatus | undefined = $state()
    let blockedIps: BlockedIpInfo[] | undefined = $state()
    let lockedUsers: LockedUserInfo[] | undefined = $state()

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

    onMount(() => {
        const refreshTimer = setInterval(load, 30_000)
        return () => {
            clearInterval(refreshTimer)
        }
    })

    async function unblockIp(ip: string) {
        if (!confirm(`Unblock ${ip}? This allows new login attempts from this address.`)) { return }
        try {
            await api.unblockIp({ ip })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function unlockUser(username: string) {
        if (!confirm(`Unlock ${username}? This allows the account to log in immediately.`)) { return }
        try {
            await api.unlockUser({ username })
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
<div class="page-summary-bar">
    <h1>login protection</h1>
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
            <StatCard
                class="flex-grow-1"
                color={status.blockedIpCount > 0 ? 'danger' : undefined}
                value={status.blockedIpCount}
                label="blocked IPs"
            />
            <StatCard
                class="flex-grow-1"
                color={status.lockedUserCount > 0 ? 'warning' : undefined}
                value={status.lockedUserCount}
                label="locked users"
            />
            <StatCard
                class="flex-grow-1"
                value={status.failedAttemptsLastHour}
                label="failed attempts (1h)"
            />
            <StatCard
                class="flex-grow-1"
                value={status.failedAttemptsLast24h}
                label="failed attempts (24h)"
            />
        </div>
    {/if}

    {#if blockedIps && (blockedIps.length > 0)}
        <div class="section-header">
            <h5 class="m-0">Blocked IPs</h5>
            <span class="badge text-bg-danger">{blockedIps.length}</span>
        </div>
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
                        <AsyncButton class="ms-auto" color="link" click={() => unblockIp(ip.ipAddress)}>Unblock</AsyncButton>
                    </div>
                </div>
            {/each}
        </div>
    {/if}

    {#if lockedUsers && (lockedUsers.length > 0)}
        <div class="section-header">
            <h5 class="m-0">Locked users</h5>
            <span class="badge text-bg-warning">{lockedUsers.length}</span>
        </div>
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
                        <AsyncButton class="ms-auto" color="link" click={() => unlockUser(user.username)}>Unlock</AsyncButton>
                    </div>
                </div>
            {/each}
        </div>
    {/if}
{/if}
</div>

<style lang="scss">
    .stats-row {
        display: flex;
        gap: 1rem;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
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
</style>
