<script lang="ts">
    import Router, { link } from 'svelte-spa-router'
    import active from 'svelte-spa-router/active'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/': wrap({
            asyncComponent: () => import('./Home.svelte')
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte')
        }),
        '/recordings/:id': wrap({
            asyncComponent: () => import('./Recording.svelte')
        }),
        '/tickets': wrap({
            asyncComponent: () => import('./Tickets.svelte')
        }),
        '/tickets/create': wrap({
            asyncComponent: () => import('./CreateTicket.svelte')
        }),
        '/ssh/known-hosts': wrap({
            asyncComponent: () => import('./SSHKnownHosts.svelte')
        }),
    }
</script>

<div class="app container">
    <header>
        <div class="logo">Warpgate</div>
        <a use:link use:active href="/">Sessions</a>
        <a use:link use:active href="/tickets">Tickets</a>
        <a use:link use:active href="/ssh/known-hosts">Known hosts</a>
    </header>
    <main>
        <Router {routes}/>
    </main>
    <footer>
        Footer
    </footer>
</div>

<style lang="scss">
    @import "./vars";

    .app {
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }

    header, footer {
        flex: none;
    }

    main {
        flex: 1 0 0;
    }

    header {
        display: flex;
        padding: 10px 0;
        margin: 10px 0 20px;
        border-bottom: 1px solid rgba($body-color, .75);

        a, .logo {
            font-size: 1.5rem;
        }

        a {
            margin-left: 15px;
        }
    }
</style>
