<script lang="ts">
    import { Alert, FormGroup } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { reloadServerInfo } from 'gateway/lib/store'
    import AuthPolicyEditor from './users/AuthPolicyEditor.svelte'

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
        if (!parameters) return
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

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>policies</h1>
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit global parameters."
    >
        {#if updateError}
            <Alert
                color="danger"
                dismissible
                onclose={() => { updateError = undefined }}
            >
                {updateError}
            </Alert>
        {/if}
        <Loadable promise={initPromise}>
            {#snippet children(parameters)}
                {#if parameters}
                    <form
                        bind:this={formEl}
                        oninput={refreshValidity}
                        onchange={refreshValidity}
                        onsubmit={e => { e.preventDefault(); save() }}
                    >
                        <FormGroup>
                            <!-- svelte-ignore a11y_label_has_associated_control -->
                            <label class="mb-2">
                                Default auth policy for new users
                            </label>
                            <AuthPolicyEditor
                                bind:value={parameters.defaultCredentialPolicy}
                                globalParameters={parameters}
                            />
                        </FormGroup>

                        <StickyActionBar>
                            <AsyncButton
                                type="button"
                                class="btn btn-primary"
                                disabled={!formValid}
                                click={save}
                            >
                                Save
                            </AsyncButton>
                        </StickyActionBar>
                    </form>
                {/if}
            {/snippet}
        </Loadable>
    </PermissionGate>
</div>
