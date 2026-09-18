<script lang="ts">
    /**
     * Portal router for the redesigned UI, behind VITE_NEW_UI.
     *
     * Identical to Root.svelte except that the catch-all route mounts
     * AppNew rather than App. The in-browser client routes are deliberately
     * the same components: WebSsh and WebDesktop are chrome-only migrations
     * scheduled with the client work, and their internals are out of scope.
     */
    import Router, { type WrappedComponent } from 'svelte-spa-router'
    import wrap from 'svelte-spa-router/wrap'

    const appRoute = wrap({
        asyncComponent: () => import('./AppNew.svelte'),
    })
    const routes: Record<string, WrappedComponent> = {
        '/web-ssh/start/:targetId': wrap({
            asyncComponent: () => import('./WebSsh.svelte'),
        }),
        // Dev-only token reference. Registered here rather than inside
        // App.svelte so it renders without a session — App gates every route
        // on requireLogin. `import.meta.env.DEV` is replaced with `false` in a
        // production build, so the chunk is never emitted.
        ...(import.meta.env.DEV
            ? {
                  '/styleguide': wrap({
                      asyncComponent: () =>
                          import('../styleguide/Styleguide.svelte'),
                  }),
              }
            : {}),
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
