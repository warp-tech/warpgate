<script lang="ts">
    // import logo from './assets/svelte.png';
    import Counter from './lib/Counter.svelte'
    import { Spinner, Button } from 'sveltestrap'

    import { onDestroy } from 'svelte'
    let sessions: any[]|null = null
    let activeSession

    async function reloadSessions () {
        sessions = (await (await fetch('/api/sessions')).json()).sessions
    }

    async function closeAllSesssions () {
        await fetch('/api/sessions', { method: 'DELETE' })
    }

    reloadSessions()
    const interval = setInterval(reloadSessions, 1000)
    onDestroy(() => clearInterval(interval))
</script>

<main class="container">
    <!-- <img src={logo} alt="Svelte Logo" />
    <h1>Hello Typescript!</h1> -->

    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Navbar</a>
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link active" href="/">Home</a>
                </li>
            </ul>
        </div>
    </nav>

    <Button on:click={closeAllSesssions}>Close all sessions</Button>

    {#if !sessions}
        <Spinner />
    {:else}
        <div class="list-group list-group-flush">
            {#each sessions as session, i}
                <a
                    class="list-group-item list-group-item-action"
                    href="/sessions/{session.id}"
                    class:active={i == 0}>
                    {session.id}:
                    {#if session.user }
                        User: <code>{session.user.username}</code>
                    {/if}
                    {#if session.target }
                        Target: <code>{session.target.host}:{session.target.port}</code>
                    {/if}
                </a>
            {/each}
        </div>
    {/if}
</main>

<style>

</style>
