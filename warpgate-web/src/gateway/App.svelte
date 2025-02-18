<script lang="ts">
    import Router, { push, type RouteDetail } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'
    import { get } from 'svelte/store'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import ThemeSwitcher from 'common/ThemeSwitcher.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import AuthBar from 'common/AuthBar.svelte'
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'

    let redirecting = false
    let serverInfoPromise = reloadServerInfo()

    async function init () {
        await serverInfoPromise
    }

    function onPageResume () {
        redirecting = false
        init()
    }

    async function requireLogin (detail: RouteDetail) {
        await serverInfoPromise
        if (!get(serverInfo)?.username) {
            let url = location.pathname + '#' + detail.location
            if (detail.querystring) {
                url += '?' + detail.querystring
            }
            push('/login?next=' + encodeURIComponent(url))
            return false
        }
        return true
    }

    const routes = {
        '/': wrap({
            asyncComponent: () => import('./TargetList.svelte') as any,
            props: {
                'on:navigation': () => redirecting = true,
            },
            conditions: [requireLogin],
        }),
        '/profile': wrap({
            asyncComponent: () => import('./Profile.svelte') as any,
            conditions: [requireLogin],
        }),
        '/profile/api-tokens': wrap({
            asyncComponent: () => import('./ProfileApiTokens.svelte') as any,
            conditions: [requireLogin],
        }),
        '/profile/credentials': wrap({
            asyncComponent: () => import('./ProfileCredentials.svelte') as any,
            conditions: [requireLogin],
        }),
        '/login': wrap({
            asyncComponent: () => import('./Login.svelte') as any,
        }),
        '/login/:stateId': wrap({
            asyncComponent: () => import('./OutOfBandAuth.svelte') as any,
            conditions: [requireLogin],
        }),
    }

    const initPromise = init()
</script>

<svelte:window on:pageshow={onPageResume}/>

<div class="container">
    <Loadable promise={initPromise}>
        {#if redirecting}
            <DelayedSpinner />
        {:else}
            <div class="d-flex align-items-center mt-5 mb-5">
                <a class="logo" href="/@warpgate">
                    <Brand />
                </a>

                <AuthBar />
            </div>

            <main>
                <Router {routes}/>
            </main>

            <footer class="mt-5">
                {#if $serverInfo?.version}
                <span class="ms-3 me-auto">
                    v{$serverInfo.version}
                </span>
                {:else}
                <div class="me-auto"></div>
                {/if}
                <ThemeSwitcher />
            </footer>
        {/if}
    </Loadable>
</div>

<style lang="scss">
    .container {
        width: 500px;
        max-width: 100vw;
    }
</style>
