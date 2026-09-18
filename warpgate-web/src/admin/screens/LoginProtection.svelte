<script lang="ts">
    /**
     * Login protection — screen 9.
     *
     * ── Enumeration of admin/status/LoginProtection.svelte ───────────────
     * Data:    getSecurityStatus + listBlockedIps + listLockedUsers, in
     *          parallel; loading and error state; 30s auto-refresh cleared on
     *          unmount; error banner with dismiss and Retry; delayed spinner
     *          while loading with no status yet.
     * Stats:   blockedIpCount (danger when > 0), lockedUserCount (warning
     *          when > 0), failedAttemptsLastHour, failedAttemptsLast24h.
     * IPs:     ipAddress, "Block #N", expiresAt as a relative date, Unblock
     *          behind a confirmation, then reload.
     * Users:   username, expiresAt as a relative date OR "manual unlock
     *          required" when absent, Unlock behind a confirmation, then
     *          reload.
     * Both lists are hidden entirely when empty, as before.
     *
     * ── One table, two sources ───────────────────────────────────────────
     * The mockup unifies blocked IPs and locked users into a single
     * "Currently blocked" table, and the two models line up well enough to do
     * it honestly: both carry a subject, a reason, a blocked-at and an
     * expiry. It is also the better answer operationally — during an incident
     * "what is currently blocked" is one question, not two. The row's kind
     * decides the marker, the action and its wording.
     *
     * `reason`, `blockedAt` and `lockedAt` are real fields the old screen
     * never displayed. Surfacing them is not invention.
     *
     * ── The entire Enforcement policy panel is omitted ───────────────────
     * The mockup's centrepiece — max failed attempts per IP and per user, IP
     * block duration, user lockout duration, an exponential-backoff switch
     * with its formula, trusted IP ranges, Save and Reset — has NO API. The
     * admin surface is exactly three readers (getSecurityStatus,
     * listBlockedIps, listLockedUsers) and two writers (unblockIp,
     * unlockUser). These are Warpgate config-file settings; there is no
     * endpoint that reads them and none that writes them. Rendering the panel
     * would mean building a form that silently discards everything typed into
     * it, so it is omitted rather than faked.
     *
     * Also omitted, for the same reason: "Purge Expired" (no endpoint),
     * "IPTABLES SYNC: REALTIME" and the "SHIELD // BASTION POLICIES" eyebrow
     * (invented chrome), the failures sparkline and "47 events" (no time
     * series), "+18%" (no historical comparison), "Peak 41/hr @ 04:00",
     * "TOTAL BLOCKS (ALL-TIME)", and the ACTIVE ISOLATION / SUSPENDED badges.
     *
     * The Attempts column is omitted too, and this one is a trap rather than
     * a gap: `blockCount` is the number of times this address has been
     * blocked, not the number of attempts it made. Labelling it "Attempts"
     * would be wrong by a wide margin for a repeat offender, so it is shown
     * as "Blocks" and only for IP rows, which are the only ones that have it.
     */
    import {
        api,
        type BlockedIpInfo,
        type LockedUserInfo,
        type SecurityStatus,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import { onMount } from 'svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import Spinner from 'ui/Spinner.svelte'
    import StatCard from 'ui/StatCard.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'

    const REFRESH_MS = 30_000

    type Row =
        | { kind: 'ip'; key: string; info: BlockedIpInfo }
        | { kind: 'user'; key: string; info: LockedUserInfo }

    let loading = $state(true)
    let error: string | undefined = $state()
    let status: SecurityStatus | undefined = $state()
    let blockedIps: BlockedIpInfo[] = $state([])
    let lockedUsers: LockedUserInfo[] = $state([])
    let pending: Row | undefined = $state()

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
        const refreshTimer = setInterval(load, REFRESH_MS)
        return () => {
            clearInterval(refreshTimer)
        }
    })

    const rows: Row[] = $derived([
        ...blockedIps.map(
            info => ({ kind: 'ip', key: `ip:${info.ipAddress}`, info }) as Row,
        ),
        ...lockedUsers.map(
            info =>
                ({ kind: 'user', key: `user:${info.username}`, info }) as Row,
        ),
    ])

    function subjectOf(row: Row): string {
        return row.kind === 'ip' ? row.info.ipAddress : row.info.username
    }

    async function confirmRelease() {
        const row = pending
        if (!row) {
            return
        }
        try {
            if (row.kind === 'ip') {
                await api.unblockIp({
                    unblockIpRequest: { ip: row.info.ipAddress },
                })
            } else {
                await api.unlockUser({ username: row.info.username })
            }
            await load()
        } catch (err) {
            error = await stringifyError(err)
        } finally {
            pending = undefined
        }
    }
</script>

<div class="head">
    <div>
        <h1>Login protection</h1>
        <p class="lede">
            Brute-force defences for all authentication endpoints.
        </p>
    </div>
</div>

{#if error}
    <div class="banner">
        <Callout tone="danger" title="Could not load login protection">
            {error}
            {#snippet actions()}
                <Button size="compact" click={load}>Retry</Button>
                <Button
                    size="compact"
                    variant="ghost"
                    onclick={() => (error = undefined)}
                >
                    Dismiss
                </Button>
            {/snippet}
        </Callout>
    </div>
{/if}

{#if loading && !status}
    <div class="loading">
        <Spinner delay={1000} label="Loading login protection status" />
    </div>
{:else}
    {#if status}
        {@const s = status}
        <div class="stats">
            <StatCard
                label="Blocked IPs"
                value={s.blockedIpCount}
                tone={s.blockedIpCount > 0 ? 'danger' : 'neutral'}
                note={s.blockedIpCount > 0 ? 'actively refused' : 'none'}
            />
            <StatCard
                label="Locked users"
                value={s.lockedUserCount}
                tone={s.lockedUserCount > 0 ? 'warning' : 'neutral'}
                note={s.lockedUserCount > 0 ? 'cannot sign in' : 'none'}
            />
            <StatCard
                label="Failed attempts (1h)"
                value={s.failedAttemptsLastHour}
            />
            <StatCard
                label="Failed attempts (24h)"
                value={s.failedAttemptsLast24h}
            />
        </div>
    {/if}

    <h2>Currently blocked</h2>

    {#if rows.length}
        <div class="table-wrap">
            <table>
                <caption class="wg-sr-only">
                    Blocked IP addresses and locked user accounts
                </caption>
                <thead>
                    <tr>
                        <th scope="col">Source</th>
                        <th scope="col">Reason</th>
                        <th scope="col" class="num">Blocks</th>
                        <th scope="col">Since</th>
                        <th scope="col">Releases</th>
                        <th scope="col">
                            <span class="wg-sr-only">Actions</span>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {#each rows as row (row.key)}
                        <tr>
                            <td>
                                <StatusMarker
                                    kind={row.kind === 'ip'
                                        ? 'blocked'
                                        : 'pending'}
                                    label={row.kind === 'ip'
                                        ? 'IP blocked'
                                        : 'User locked'}
                                    bare
                                />
                                <span class="wg-mono subject">
                                    {subjectOf(row)}
                                </span>
                            </td>
                            <td class="muted">{row.info.reason}</td>
                            <td class="num">
                                {#if row.kind === 'ip'}
                                    {row.info.blockCount}
                                {:else}
                                    <span class="muted">&mdash;</span>
                                {/if}
                            </td>
                            <td class="muted">
                                <RelativeDate
                                    date={row.kind === 'ip'
                                        ? row.info.blockedAt
                                        : row.info.lockedAt}
                                />
                            </td>
                            <td>
                                {#if row.info.expiresAt}
                                    <RelativeDate date={row.info.expiresAt} />
                                {:else}
                                    <span class="manual">
                                        Manual unlock required
                                    </span>
                                {/if}
                            </td>
                            <td class="num">
                                <Button
                                    variant="ghost"
                                    size="compact"
                                    onclick={() => (pending = row)}
                                >
                                    {row.kind === 'ip' ? 'Unblock' : 'Unlock'}
                                </Button>
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {:else}
        <EmptyState
            title="Nothing is blocked"
            hint="Addresses and accounts appear here once they trip the configured failure thresholds."
        />
    {/if}

    <p class="footnote">
        Thresholds and block durations are set in the Warpgate configuration
        file, not here. This page shows what they are currently doing.
    </p>
{/if}

<ConfirmDialog
    open={!!pending}
    title={pending?.kind === 'ip'
        ? 'Unblock this address?'
        : 'Unlock this account?'}
    confirmLabel={pending?.kind === 'ip' ? 'Unblock' : 'Unlock'}
    onconfirm={confirmRelease}
    oncancel={() => (pending = undefined)}
>
    {#if pending}
        {@const p = pending}
        <p class="panel">
            {#if p.kind === 'ip'}
                <strong class="wg-mono">{p.info.ipAddress}</strong>
                can make login attempts again immediately. It was blocked
                because:
                {p.info.reason}. If the attempts were hostile they will resume,
                and the address will be blocked again once it trips the
                threshold.
            {:else}
                <strong class="wg-mono">{p.info.username}</strong>
                can sign in again immediately. The account was locked because:
                {p.info.reason}. If you did not expect this lockout, confirm
                with the account holder before unlocking — a lockout is also
                what a password-guessing attempt looks like from this side.
            {/if}
        </p>
    {/if}
</ConfirmDialog>

<style>
    .head {
        margin-bottom: var(--wg-space-lg);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    h2 {
        margin: var(--wg-space-2xl) 0 var(--wg-space-md);
        font: var(--wg-text-headline-md);
    }

    .lede {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .banner,
    .loading {
        margin-bottom: var(--wg-space-lg);
    }

    .loading {
        display: flex;
        justify-content: center;
        padding: var(--wg-space-3xl) 0;
    }

    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
        gap: var(--wg-space-md);
    }

    .table-wrap {
        overflow-x: auto;
    }

    table {
        width: 100%;
        border-collapse: collapse;
    }

    th {
        padding: var(--wg-space-sm) var(--wg-space-md);
        text-align: left;
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
        background: var(--wg-surface-container);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        white-space: nowrap;
    }

    td {
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        vertical-align: middle;
    }

    .subject {
        margin-left: var(--wg-space-xs);
    }

    .num {
        text-align: right;
    }

    .muted {
        color: var(--wg-text-muted);
    }

    .manual {
        color: var(--wg-secondary);
    }

    .footnote {
        margin: var(--wg-space-xl) 0 0;
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
        max-width: 70ch;
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }

    .wg-sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
