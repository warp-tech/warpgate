<script lang="ts">
    import { useSidebar } from 'common/sidebarState.svelte'
    import Router from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/sessions': wrap({
            asyncComponent: () => import('./Sessions.svelte'),
        }),
        '/sessions/:id': wrap({
            asyncComponent: () => import('./Session.svelte'),
        }),
        '/requests': wrap({
            asyncComponent: () => import('./Requests.svelte'),
        }),
        '/login-protection': wrap({
            asyncComponent: () => import('./LoginProtection.svelte'),
        }),
        '/network': wrap({
            asyncComponent: () => import('./NetworkStatus.svelte'),
        }),
    }

    useSidebar(() => [
        {
            title: 'Sessions',
            href: '/status/sessions',
        },
        {
            title: 'Requests',
            href: '/status/requests',
        },
        {
            title: 'Login protection',
            href: '/status/login-protection',
        },
        {
            title: 'Network status',
            href: '/status/network',
        },
    ])
</script>

<Router {routes} prefix="/status" />
