<script lang="ts">
    import Fa from 'svelte-fa'
    import { faCircleDot as iconActive } from '@fortawesome/free-regular-svg-icons'
    import { faMinus as  iconInactive} from '@fortawesome/free-solid-svg-icons'
    import { Spinner, Button } from 'sveltestrap'
    import { onDestroy } from 'svelte'
    import { link } from 'svelte-spa-router'
    import { reloadSessions, sessions } from './lib/state'
    import { api, SessionSnapshot } from 'lib/api'
    import { derived } from 'svelte/store'
    import { firstBy } from 'thenby'
    import moment from 'moment'
    import RelativeDate from 'RelativeDate.svelte'

    async function closeAllSesssions () {
        await api.closeAllSessions()
    }

    function describeSession (session: SessionSnapshot): string {
        let user = session.username ?? '<logging in>'
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

<main>
    {#if !sessions}
        <Spinner />
    {:else}
        <div class="list-group list-group-flush">
            {#if $sortedSessions }
                <div class="page-summary-bar">
                    {#if $activeSessions }
                        <h1>Sessions right now: {$activeSessions}</h1>
                        <Button class="ms-auto" outline={true} on:click={closeAllSesssions}>
                            Close all sessions
                        </Button>
                    {:else}
                        <h1>No active sessions</h1>
                    {/if}
                </div>

                {#each $sortedSessions as session}
                    <a
                        class="list-group-item list-group-item-action"
                        href="/sessions/{session.id}"
                        use:link>
                        <div class="main">
                            <div class="icon" class:text-success={!session.ended}>
                                <Fa icon={session.ended ? iconInactive : iconActive} fw />
                            </div>
                            <strong>
                                {describeSession(session)}
                            </strong>

                            <!-- {#if session.username }
                            <div>
                                User: <code>{session.username}</code>
                            </div>
                            {/if}

                            {#if session.target }
                            <div>
                                Target: <code>{session.target.ssh?.host}:{session.target.ssh?.port}</code>
                                {/if}
                            </div> -->

                            <div class="meta">
                                {#if session.ended }
                                    {moment.duration(moment(session.ended).diff(session.started)).humanize()}
                                {:else}
                                    {moment.duration(moment().diff(session.started)).humanize()}
                                {/if}
                            </div>

                            <div class="meta ms-auto">
                                <RelativeDate date={session.started} />
                            </div>
                        </div>
                    </a>
                {/each}
            {/if}
        </div>
    {/if}
</main>

<style lang="scss">
    .list-group-item {
        .icon {
            display: flex;
            align-items: center;
            margin-right: 5px;
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
