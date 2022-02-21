<script lang="ts">
    import Router, { link } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/': wrap({
            asyncComponent: () => import('./Home.svelte')
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte')
        })
    }
</script>

<main class="container">
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/" use:link>Navbar</a>
            <ul class="navbar-nav me-auto">
                <li class="nav-item">
                    <a class="nav-link active" href="/" use:link>Home</a>
                </li>
            </ul>
        </div>
    </nav>
    <Router {routes}/>
</main>
