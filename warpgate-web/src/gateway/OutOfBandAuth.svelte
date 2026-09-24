<script lang="ts">
    import { formatDurationAsHumantime } from 'common/duration'
    import { errorStatus } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import {
        ApiAuthState,
        ApprovalScope,
        type AuthStateResponseInternal,
        api,
    } from 'gateway/lib/api'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Menu from 'ui/Menu.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'

    interface Props {
        params: { stateId: string }
    }

    let { params }: Props = $props()

    let authState: AuthStateResponseInternal | undefined = $state()

    let cachingGrace = $derived(authState?.webApprovalCachingGraceSeconds ?? 0)
    let cachingEnabled = $derived(cachingGrace > 0)
    let graceLabel = $derived(formatDurationAsHumantime(cachingGrace))

    async function init() {
        try {
            authState = await api.getAuthState({ id: params.stateId })
        } catch (err) {
            // The link is printed by a client and followed later, in whatever
            // browser session the user happens to have — so landing on a
            // request that has finished, or on someone else's, is ordinary.
            if (errorStatus(err) === 404) {
                throw new Error(
                    'This request is no longer waiting. It may have been answered already, timed out, or belong to a different account than the one you are signed in as.',
                )
            }
            throw err
        }
    }

    // The endpoints return only whether the decision was recorded, and the
    // request is no longer pending afterwards, so re-reading it would 404 on
    // any node that isn't holding the login. `window.close()` is a courtesy —
    // a browser that refuses it for a page the user opened themselves leaves
    // this showing the outcome.
    function resolved(state: ApiAuthState) {
        if (authState) {
            authState = { ...authState, state }
        }
        window.close()
    }

    async function approve(scope: ApprovalScope) {
        await api.approveAuth({
            id: params.stateId,
            approveAuthRequest: { scope },
        })
        resolved(ApiAuthState.Success)
    }

    async function reject() {
        await api.rejectAuth({ id: params.stateId })
        resolved(ApiAuthState.Failed)
    }
</script>

<style lang="scss">
    .identification-string {
        display: flex;
        font-size: 3rem;

        .card {
            padding: 0rem 0.5rem;
            border-radius: .5rem;
            margin-right: .5rem;
        }
    }

    .approve-group {
        display: flex;
        align-items: center;
        gap: var(--wg-space-xs);
    }
</style>

<Loadable promise={init()}>
    {#if authState}
        <div class="page-summary-bar">
            <h1>authorization request</h1>
        </div>

        <div class="mb-5">
            <div class="mb-2">
                Ensure this security key matches your authentication prompt:
            </div>
            <div class="identification-string">
                {#each authState?.identificationString as char}
                    <div class="card bg-secondary text-light">
                        <div class="card-body">{char}</div>
                    </div>
                {/each}
            </div>
        </div>

        <div class="mb-3">
            <div>Authorize this {authState.protocol} session?</div>
            <small>
                Requested <RelativeDate date={authState.started} />
                {#if authState.address}
                    from {authState.address}
                {/if}
            </small>
        </div>

        {#if authState.state === ApiAuthState.Success}
            <Callout tone="success"> Approved </Callout>
        {:else if authState.state === ApiAuthState.Failed}
            <Callout tone="danger" title="Something went wrong">
                Rejected
            </Callout>
        {:else}
            <div class="d-flex">
                <div class="ms-auto"></div>
                {#if cachingEnabled}
                    <!--
                      Was a sveltestrap split button: a primary action plus a
                      caret-only DropdownToggle with no accessible name at all.
                      ui/Menu's trigger carries one, and the default action
                      stays a separate button so it is still one click.
                    -->
                    <div class="approve-group">
                        <Button
                            variant="primary"
                            click={() => approve(ApprovalScope.Target)}
                        >
                            Authorize &amp; remember for {graceLabel}
                        </Button>
                        <Menu
                            label="More authorize options"
                            align="end"
                            groups={[
                                {
                                    items: [
                                        {
                                            id: 'all',
                                            label: `Authorize for all targets & remember for ${graceLabel}`,
                                            onselect: () =>
                                                approve(
                                                    ApprovalScope.AllTargets,
                                                ),
                                        },
                                        {
                                            id: 'once',
                                            label: 'Authorize this time only',
                                            onselect: () =>
                                                approve(ApprovalScope.Once),
                                        },
                                    ],
                                },
                            ]}
                        />
                    </div>
                {:else}
                    <Button
                        variant="primary"
                        click={() => approve(ApprovalScope.Once)}
                    >
                        Authorize
                    </Button>
                {/if}
                <Button
                    variant="secondary"
                    class="d-flex align-items-center ms-2"
                    click={reject}
                >
                    Reject
                </Button>
            </div>
        {/if}
    {/if}
</Loadable>
