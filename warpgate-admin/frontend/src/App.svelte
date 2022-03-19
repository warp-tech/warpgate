<script lang="ts">
    import Router, { link } from 'svelte-spa-router'
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

<main class="container">
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/" use:link>Navbar</a>
            <ul class="navbar-nav me-auto flex-row">
                <li class="nav-item me-3">
                    <a class="nav-link active" href="/" use:link>Sessions</a>
                </li>
                <li class="nav-item me-3">
                    <a class="nav-link active" href="/tickets" use:link>Tickets</a>
                </li>
                <li class="nav-item me-3">
                    <a class="nav-link active" href="/ssh/known-hosts" use:link>Known hosts</a>
                </li>
            </ul>
        </div>
    </nav>
    <Router {routes}/>
</main>
