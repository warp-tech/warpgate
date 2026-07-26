<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import type { Snippet } from 'svelte'
    import Router, {
        type RouteDefinition,
        type RouteDetail,
        type WrappedComponent,
    } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'

    interface Props {
        routes: Record<string, WrappedComponent>
        prefix: string
        navItems: Snippet<[sidebarMode: boolean]>
    }

    const { routes, prefix, navItems }: Props = $props()

    let sidebarMode = $state(false)

    function onRouteLoading(detail: RouteDetail) {
        sidebarMode = detail.route !== ''
    }
</script>

<div class="wrapper" class:d-none={!sidebarMode}>
    <div class="sidebar">
        {@render navItems(sidebarMode)}
    </div>

    <div class="main">
        <Router {routes} {prefix} {onRouteLoading} />
    </div>
</div>

{#if !sidebarMode}
    <div class="container-max-md m-auto">
        {@render navItems(false)}
    </div>
{/if}

<style lang="scss">
    $sb-w: 270px;
    $sb-m: 30px;

    .wrapper {
        display: flex;
        gap: $sb-m;

        > .sidebar {
            width: $sb-w;
            flex: none;
        }

        > .main {
            flex: 1 0 0;
            max-width: 100%;
        }
    }

    @media (max-width: #{720px + $sb-m + $sb-w}) {
        .sidebar {
            display: none;
        }
    }
</style>
