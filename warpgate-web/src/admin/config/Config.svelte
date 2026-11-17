<script lang="ts">
    import Redirect from 'common/Redirect.svelte'
    import { useSidebar } from 'common/sidebarState.svelte'
    import Router from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/parameters': wrap({
            component: Redirect,
            props: { to: '/config/parameters/auth' },
        }),
        '/parameters/auth': wrap({
            asyncComponent: () => import('./parameters/Auth.svelte'),
        }),
        '/parameters/login-protection': wrap({
            asyncComponent: () => import('./parameters/LoginProtection.svelte'),
        }),
        '/parameters/ui': wrap({
            asyncComponent: () => import('./parameters/Ui.svelte'),
        }),
        '/parameters/network': wrap({
            asyncComponent: () => import('./parameters/Network.svelte'),
        }),
        '/parameters/ssh': wrap({
            asyncComponent: () => import('./parameters/Ssh.svelte'),
        }),
        '/parameters/session-approvals': wrap({
            asyncComponent: () =>
                import('./parameters/SessionApprovals.svelte'),
        }),
        '/parameters/recordings': wrap({
            asyncComponent: () => import('./parameters/Recordings.svelte'),
        }),
        '/parameters/installation-counter': wrap({
            asyncComponent: () =>
                import('./parameters/InstallationCounter.svelte'),
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
            title: 'Authentication',
            href: '/config/parameters/auth',
        },
        {
            title: 'Recordings',
            href: '/config/parameters/recordings',
        },
        {
            title: 'UI',
            href: '/config/parameters/ui',
        },
        {
            title: 'Session approvals',
            href: '/config/parameters/session-approvals',
        },
        {
            title: 'Login protection',
            href: '/config/parameters/login-protection',
        },
        {
            title: 'SSH',
            href: '/config/parameters/ssh',
        },
        {
            title: 'Network',
            href: '/config/parameters/network',
        },
        {
            title: 'Secret backends',
            href: '/config/secret-backends',
        },
        {
            title: 'LDAP servers',
            href: '/config/ldap-servers',
        },
        {
            title: 'Installation counter',
            href: '/config/parameters/installation-counter',
        },
    ])
</script>

<Router {routes} prefix="/config" />
