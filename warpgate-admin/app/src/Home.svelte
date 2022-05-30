<script lang="ts">
    import { Fa } from 'svelte-fa'
    import { faCircleDot as iconActive } from '@fortawesome/free-regular-svg-icons'
    import { Spinner, Button } from 'sveltestrap'
    import { onDestroy } from 'svelte'
    import { link } from 'svelte-spa-router'
    import { api, SessionSnapshot } from 'lib/api'
    import { derived, writable } from 'svelte/store'
    import { firstBy } from 'thenby'
    import moment, { duration } from 'moment'
    import RelativeDate from 'RelativeDate.svelte'

    const sessions = writable<SessionSnapshot[]|null>(null)

    async function reloadSessions (): Promise<void> {
        sessions.set(await api.getSessions())
    }

    async function closeAllSesssions () {
        await api.closeAllSessions()
    }

    function describeSession (session: SessionSnapshot): string {
        let user = session.username ?? (session.ended ? '<not logged in>' : '<logging in>')
        if (!session.target) {
            return user
        }
        let target = session.target.name
        return `${user} on ${target}`
    }


    let activeSessions = derived(sessions, s => s?.filter(x => !x.ended).length ?? 0)
    let sortedSessions = derived(sessions, s => s?.sort(
        firstBy<SessionSnapshot, boolean>(x => !!x.ended, 'asc')
            .thenBy(x => x.ended ?? x.started, 'desc')
    ))
    reloadSessions()
    const interval = setInterval(reloadSessions, 1000)
    onDestroy(() => clearInterval(interval))
</script>

{#if !sessions}
    <Spinner />
{:else}
    <div class="page-summary-bar">
        {#if $activeSessions }
            <h1>Sessions right now: {$activeSessions}</h1>
            <Button class="ms-auto" outline on:click={closeAllSesssions}>
                Close all sessions
            </Button>
        {:else}
            <h1>No active sessions</h1>
        {/if}
    </div>

    {#if $sortedSessions }
        <div class="list-group list-group-flush">
            {#each $sortedSessions as session}
                <a
                    class="list-group-item list-group-item-action"
                    href="/sessions/{session.id}"
                    use:link>
                    <div class="main">
                        <div class="icon" class:text-success={!session.ended}>
                            {#if !session.ended}
                                <Fa icon={iconActive} fw />
                            {/if}
                        </div>
                        <strong>
                            {describeSession(session)}
                        </strong>

                        <div class="meta">
                            {#if session.ended }
                                {duration(moment(session.ended).diff(session.started)).humanize()}
                            {/if}
                        </div>

                        <div class="meta ms-auto">
                            <RelativeDate date={session.started} />
                        </div>
                    </div>
                </a>
            {/each}
        </div>
    {/if}
{/if}

<style lang="scss">
    .list-group-item {
        .icon {
            display: flex;
            align-items: center;
            margin-right: 5px;
            width: 20px;
        }

        .main {
            display: flex;
            align-items: center;
        }

        .meta {
            opacity: .75;
            margin-left: 25px;
            font-size: .75rem;
        }
    }
</style>
