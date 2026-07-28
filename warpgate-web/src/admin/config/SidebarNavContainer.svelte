<script lang="ts">
    import { faArrowLeft, faNavicon } from '@fortawesome/free-solid-svg-icons'
    import { Button } from '@sveltestrap/sveltestrap'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'
    import Router, {
        link,
        type RouteDetail,
        type WrappedComponent,
    } from 'svelte-spa-router'

    interface Props {
        routes: Record<string, WrappedComponent>
        prefix: string
        returnLink?: boolean
        navItems: Snippet<[sidebarMode: boolean]>
    }

    const { routes, prefix, returnLink, navItems }: Props = $props()

    let sidebarMode = $state(false)

    function onRouteLoading(detail: RouteDetail) {
        sidebarMode = detail.route !== ''
    }
</script>

<div class="wrapper" class:d-none={!sidebarMode}>
    {#if returnLink}
        <a
            class="nav-return-link btn btn-link"
            use:link
            href={prefix}
            color="link"
        >
            <Fa icon={faArrowLeft} size="lg" />
        </a>
    {/if}
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

        > .sidebar {
            width: $sb-w;
            margin-right: $sb-m;
            flex: none;
        }

        > .main {
            flex: 1 0 0;
            min-width: 0;
            max-width: 100%;
        }
    }

    .nav-return-link {
        display: none;
        margin-top: 12px;
    }

    @media (max-width: #{720px + $sb-m + $sb-w}) {
        .sidebar {
            display: none;
        }

        .nav-return-link {
            display: block;
        }
    }
</style>
