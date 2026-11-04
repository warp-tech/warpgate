<script lang="ts">
    import { useSidebar } from 'common/sidebarState.svelte'
    import Router from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/parameters': wrap({
            asyncComponent: () => import('./Parameters.svelte'),
        }),
        '/ldap-servers': wrap({
            asyncComponent: () => import('./ldap/LdapServers.svelte'),
        }),
        '/ldap-servers/create': wrap({
            asyncComponent: () => import('./ldap/CreateLdapServer.svelte'),
        }),
        '/ldap-servers/:id': wrap({
            asyncComponent: () => import('./ldap/LdapServer.svelte'),
        }),
        '/ldap-servers/:id/users': wrap({
            asyncComponent: () => import('./ldap/LdapUserBrowser.svelte'),
        }),
        '/secret-backends': wrap({
            asyncComponent: () =>
                import('./secret-backends/SecretBackends.svelte'),
        }),
    }

    useSidebar(() => [
        {
            title: 'Global parameters',
            href: '/config/parameters',
        },
        {
            title: 'LDAP servers',
            href: '/config/ldap-servers',
        },
        {
            title: 'Secret backends',
            href: '/config/secret-backends',
        },
    ])
</script>

<Router {routes} prefix="/config" />
