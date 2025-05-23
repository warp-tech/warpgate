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
    import { api, type AuthStateResponseInternal } from './lib/api'
    import { Button } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'

    let redirecting = $state(false)
    let serverInfoPromise = reloadServerInfo()
    let webAuthRequests: AuthStateResponseInternal[] = $state([])
    let doNotShowAuthRequests = $state(false)

    async function init () {
        await serverInfoPromise
    }

    function onPageResume () {
        redirecting = false
    }

    async function reloadWebAuthRequests () {
        webAuthRequests = await api.getWebAuthRequests()
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
            userData: {
                doNotShowAuthRequests: true,
            },
        }),
    }

    const initPromise = init()
    let socket: WebSocket | null = null

    $effect(() => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        $serverInfo?.username // trigger effect on username change
        try {
            socket?.close()
        } catch {
            // ignore
        }
        socket = null
        if ($serverInfo?.username) {
            socket = new WebSocket(`wss://${location.host}/@warpgate/api/auth/web-auth-requests/stream`)
            socket.addEventListener('message', () => {
                reloadWebAuthRequests()
            })
            reloadWebAuthRequests()
        }
    })
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

            {#if !doNotShowAuthRequests}
            {#each webAuthRequests as authRequest}
                <Button
                    color="success"
                    class="mb-4 d-flex align-items-center w-100 text-start"
                    on:click={() => {
                        push('/login/' + authRequest.id)
                    }}
                >
                    <div>
                        <strong class="d-block">
                            {authRequest.protocol} authentication request
                        </strong>
                        {#if authRequest.address}
                            <small>
                                From {authRequest.address}
                            </small>
                        {/if}
                    </div>
                    <Fa class="ms-auto" icon={faArrowRight} />
                </Button>
            {/each}
            {/if}

            <main>
                <Router {routes} on:routeLoaded={e => {
                    doNotShowAuthRequests = !!(e.detail.userData as any)?.['doNotShowAuthRequests']
                }} />
            </main>

            <footer class="mt-5">
                {#if $serverInfo?.version}
                <span class="ms-3 me-auto">
                    {$serverInfo.version}
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
