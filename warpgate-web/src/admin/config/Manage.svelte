<script lang="ts">
    import { useSidebar } from 'common/sidebarState.svelte'
    import Router from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    const routes = {
        '/targets/create/:kind': wrap({
            asyncComponent: () => import('./targets/CreateTarget.svelte'),
        }),
        '/targets/create': wrap({
            asyncComponent: () => import('./targets/ChooseTargetKind.svelte'),
        }),
        '/targets/:id': wrap({
            asyncComponent: () => import('./targets/Target.svelte'),
        }),
        '/access-roles/create': wrap({
            asyncComponent: () => import('./CreateRole.svelte'),
        }),
        '/access-roles/:id': wrap({
            asyncComponent: () => import('./AccessRole.svelte'),
        }),
        '/admin-roles/create': wrap({
            asyncComponent: () => import('./CreateAdminRole.svelte'),
        }),
        '/admin-roles/:id': wrap({
            asyncComponent: () => import('./AdminRole.svelte'),
        }),
        '/users/create': wrap({
            asyncComponent: () => import('./CreateUser.svelte'),
        }),
        '/users/:id': wrap({
            asyncComponent: () => import('./users/User.svelte'),
        }),
        '/users': wrap({
            asyncComponent: () => import('./users/Users.svelte'),
        }),
        '/policies': wrap({
            asyncComponent: () => import('./Policies.svelte'),
        }),
        '/access-roles': wrap({
            asyncComponent: () => import('./AccessRoles.svelte'),
        }),
        '/admin-roles': wrap({
            asyncComponent: () => import('./AdminRoles.svelte'),
        }),
        '/targets': wrap({
            asyncComponent: () => import('./targets/Targets.svelte'),
        }),
        '/ssh': wrap({
            asyncComponent: () => import('./SSHKeys.svelte'),
        }),
        '/tickets': wrap({
            asyncComponent: () => import('./Tickets.svelte'),
        }),
        '/tickets/create': wrap({
            asyncComponent: () => import('./CreateTicket.svelte'),
        }),
        '/target-groups/create': wrap({
            asyncComponent: () =>
                import('./target-groups/CreateTargetGroup.svelte'),
        }),
        '/target-groups/:id': wrap({
            asyncComponent: () => import('./target-groups/TargetGroup.svelte'),
        }),
        '/target-groups': wrap({
            asyncComponent: () => import('./target-groups/TargetGroups.svelte'),
        }),
    }

    useSidebar(() => [
        {
            title: 'Targets',
            href: '/manage/targets',
        },
        {
            title: 'Target groups',
            href: '/manage/target-groups',
        },
        {
            title: 'Users',
            href: '/manage/users',
        },
        {
            title: 'Access roles',
            href: '/manage/access-roles',
        },
        {
            title: 'Admin roles',
            href: '/manage/admin-roles',
        },
        {
            title: 'Tickets',
            href: '/manage/tickets',
        },
        {
            title: 'SSH keys',
            href: '/manage/ssh',
        },
        {
            title: 'Policies',
            href: '/manage/policies',
        },
    ])
</script>

<Router {routes} prefix="/manage" />
