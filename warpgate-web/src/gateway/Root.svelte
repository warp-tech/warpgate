<script lang="ts">
    import Router, { type WrappedComponent } from 'svelte-spa-router'
    import wrap from 'svelte-spa-router/wrap'

    const routes: Record<string, WrappedComponent> = {
        '/web-ssh/:sessionId': wrap({
            asyncComponent: () => import('./WebSsh.svelte') as any,
        }),
        '/': wrap({
            asyncComponent: () => import('./App.svelte') as any,
        }),
    }
    routes['/*'] = routes['/']!

</script>

<Router {routes} />
