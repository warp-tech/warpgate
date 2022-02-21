<script lang="ts">
    // import logo from './assets/svelte.png';
    import { Spinner, Button } from 'sveltestrap'
    import { onDestroy } from 'svelte'
    import { link } from 'svelte-spa-router'
    import { reloadSessions, sessions } from './lib/state'
    import { api } from 'lib/api'

    async function closeAllSesssions () {
        await api.apiCloseAllSessions()
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
                    {session.id}:
                    {#if session.user }
                        User: <code>{session.user.username}</code>
                    {/if}
                    {#if session.target }
                        Target: <code>{session.target.host}:{session.target.port}</code>
                    {/if}
                </a>
            {/each}
            {/if}
        </div>
    {/if}
</main>

<style>

</style>
