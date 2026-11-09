<script lang="ts">
    import Router, { type WrappedComponent } from 'svelte-spa-router'
    import wrap from 'svelte-spa-router/wrap'

    const appRoute = wrap({
        asyncComponent: () => import('./App.svelte'),
    })
    const routes: Record<string, WrappedComponent> = {
        '/web-ssh/start/:targetId': wrap({
            asyncComponent: () => import('./WebSsh.svelte'),
        }),
        '/web-ssh/:sessionId': wrap({
            asyncComponent: () => import('./WebSsh.svelte'),
        }),
        '/web-desktop/start/:targetId': wrap({
            asyncComponent: () => import('./WebDesktop.svelte'),
        }),
        '/web-desktop/:sessionId': wrap({
            asyncComponent: () => import('./WebDesktop.svelte'),
        }),
        '/': appRoute,
        '/*': appRoute,
    }
</script>

<Router {routes} />
