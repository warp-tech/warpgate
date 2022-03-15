<script lang="ts">
    import Fa from 'svelte-fa'
    import { faCircle } from '@fortawesome/free-solid-svg-icons'
    // import logo from './assets/svelte.png';
    import { Spinner, Button } from 'sveltestrap'
    import { onDestroy } from 'svelte'
    import { link } from 'svelte-spa-router'
    import { reloadSessions, sessions } from './lib/state'
    import { api } from 'lib/api'

    async function closeAllSesssions () {
        await api.closeAllSessions()
    }

    reloadSessions()
    const interval = setInterval(reloadSessions, 1000)
    onDestroy(() => clearInterval(interval))
</script>

<main class="container">
    <Button on:click={closeAllSesssions}>Close all sessions</Button>

    {#if !sessions}
        <Spinner />
    {:else}
        <div class="list-group list-group-flush">
            {#if $sessions }
            {#each $sessions as session, i}
                <a
                    class="list-group-item list-group-item-action"
                    href="/sessions/{session.id}"
                    use:link
                    class:active={i === 0}>
                    <div class="main">
                        <div class:text-success={!session.ended}>
                            <Fa icon={faCircle} />
                        </div>

                        <strong>
                            {session.id}
                        </strong>

                        {#if session.username }
                        <div>
                            User: <code>{session.username}</code>
                        </div>
                        {/if}

                        {#if session.target }
                        <div>
                            Target: <code>{session.target.host}:{session.target.port}</code>
                        </div>
                        {/if}
                    </div>
                    <div class="meta">
                        <small>{session.started}</small>
                    </div>
                </a>
            {/each}
            {/if}
        </div>
    {/if}
</main>

<style lang="scss">
.list-group-item {
    .main {
        display: flex;
        align-items: center;

        > * {
            margin-right: 20px;
        }
    }

    .meta {
        opacity: .75;
    }
}
</style>
