<script lang="ts">
    import {
        Alert,
        ButtonGroup,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { formatDurationAsHumantime } from 'common/duration'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import {
        ApiAuthState,
        ApprovalScope,
        type AuthStateResponseInternal,
        api,
    } from 'gateway/lib/api'

    interface Props {
        params: { stateId: string }
    }

    let { params }: Props = $props()

    let authState: AuthStateResponseInternal | undefined = $state()

    let cachingGrace = $derived(authState?.webApprovalCachingGraceSeconds ?? 0)
    let cachingEnabled = $derived(cachingGrace > 0)
    let graceLabel = $derived(formatDurationAsHumantime(cachingGrace))

    async function init() {
        authState = await api.getAuthState({ id: params.stateId })
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
            <Alert color="success"> Approved </Alert>
        {:else if authState.state === ApiAuthState.Failed}
            <Alert color="danger"> Rejected </Alert>
        {:else}
            <div class="d-flex">
                <div class="ms-auto"></div>
                {#if cachingEnabled}
                    <ButtonGroup>
                        <AsyncButton
                            color="primary"
                            click={() => approve(ApprovalScope.Target)}
                        >
                            Authorize & remember for {graceLabel}
                        </AsyncButton>
                        <Dropdown class="btn-group">
                            <DropdownToggle
                                color="primary"
                                caret
                                class="ps-2"
                            />
                            <DropdownMenu end>
                                <DropdownItem
                                    onclick={() => approve(ApprovalScope.AllTargets)}
                                >
                                    Authorize for all targets & remember for
                                    {graceLabel}
                                </DropdownItem>
                                <DropdownItem
                                    onclick={() => approve(ApprovalScope.Once)}
                                >
                                    Authorize this time only
                                </DropdownItem>
                            </DropdownMenu>
                        </Dropdown>
                    </ButtonGroup>
                {:else}
                    <AsyncButton
                        color="primary"
                        click={() => approve(ApprovalScope.Once)}
                    >
                        Authorize
                    </AsyncButton>
                {/if}
                <AsyncButton
                    color="secondary"
                    class="d-flex align-items-center ms-2"
                    click={reject}
                >
                    Reject
                </AsyncButton>
            </div>
        {/if}
    {/if}
</Loadable>
