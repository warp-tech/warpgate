<script lang="ts">
    /**
     * Policies — restyled in place.
     *
     * Behaviour preserved: loads all parameters but submits only
     * defaultCredentialPolicy, revalidates the form on input and change, keeps
     * Save disabled while invalid, and reloads server info afterwards so the
     * rest of the app sees the new default.
     *
     * Repointed at the migrated AuthPolicyEditor rather than the old one —
     * they are the same editor and the migrated version carries the 6c
     * documentation of the inverted "Any credential" semantics.
     */
    import { api, type ParameterValues } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AuthPolicyEditor from 'admin/screens/user-detail/credentials/AuthPolicyEditor.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { reloadServerInfo } from 'gateway/lib/store'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import 'ui/layout.css'

    let parameters: ParameterValues | undefined = $state()
    let updateError: string | undefined = $state()
    let formEl: HTMLFormElement | undefined = $state()
    let formValid = $state(true)

    const initPromise = init()

    async function init() {
        parameters = await api.getParameters({})
        return parameters
    }

    function refreshValidity() {
        formValid = formEl?.checkValidity() ?? false
    }

    $effect(() => {
        // Validate once the form has rendered with loaded values.
        if (formEl && parameters) {
            refreshValidity()
        }
    })

    async function save() {
        if (!parameters) {
            return
        }
        updateError = undefined
        try {
            await api.updateParameters({
                parameterUpdate: {
                    defaultCredentialPolicy: parameters.defaultCredentialPolicy,
                },
            })
            await reloadServerInfo()
        } catch (err) {
            updateError = await stringifyError(err)
        }
    }
</script>

<div class="wg-page-head">
    <div>
        <h1>Policies</h1>
        <p class="wg-page-lede">
            What new users must present to authenticate, per protocol.
        </p>
    </div>
</div>

<PermissionGate
    perm="configEdit"
    message="You have no permission to edit global parameters."
>
    {#if updateError}
        <div class="notice">
            <Callout tone="danger" title="Could not save">
                {updateError}
                {#snippet actions()}
                    <Button
                        size="compact"
                        variant="ghost"
                        onclick={() => (updateError = undefined)}
                    >
                        Dismiss
                    </Button>
                {/snippet}
            </Callout>
        </div>
    {/if}

    <Loadable promise={initPromise}>
        {#snippet children(loaded)}
            {#if loaded}
                <form
                    bind:this={formEl}
                    oninput={refreshValidity}
                    onchange={refreshValidity}
                    onsubmit={e => {
                        e.preventDefault()
                        save()
                    }}
                >
                    <h2>Default auth policy for new users</h2>
                    <AuthPolicyEditor
                        bind:value={loaded.defaultCredentialPolicy}
                        globalParameters={loaded}
                    />

                    <StickyActionBar>
                        <Button
                            variant="primary"
                            disabled={!formValid}
                            click={save}
                        >
                            Save
                        </Button>
                    </StickyActionBar>
                </form>
            {/if}
        {/snippet}
    </Loadable>
</PermissionGate>

<style>
    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    h2 {
        margin: 0 0 var(--wg-space-md);
        font: var(--wg-text-headline-sm, var(--wg-text-headline-md));
    }
</style>
