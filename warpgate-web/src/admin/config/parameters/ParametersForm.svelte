<script lang="ts">
    import { Alert } from '@sveltestrap/sveltestrap'
    import {
        api,
        type ParameterUpdate,
        type ParameterValues,
    } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import SectionedForm from 'admin/lib/SectionedForm.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { reloadServerInfo } from 'gateway/lib/store'
    import type { Snippet } from 'svelte'

    interface Props {
        title: string
        /** Bind to keep script-level access to the loaded parameters. */
        parameters?: ParameterValues
        /**
         * Extra fields merged into the update request on save. Untyped
         * because the generated model can't express `null` as "clear".
         */
        extraUpdate?: () => Record<string, unknown>
        onsaved?: () => Promise<void> | void
        /** Sections; call `refreshValidity` after programmatic value changes. */
        children: Snippet<
            [parameters: ParameterValues, refreshValidity: () => void]
        >
    }

    let {
        title,
        parameters = $bindable(),
        extraUpdate,
        onsaved,
        children,
    }: Props = $props()

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
            // Cleared nullable fields must be sent as explicit null: undefined
            // is dropped by JSON.stringify, so the server keeps the old value.
            const parameterUpdate = {
                ...parameters,
                rateLimitBytesPerSecond:
                    parameters.rateLimitBytesPerSecond ?? null,
                ticketMaxDurationSeconds:
                    parameters.ticketMaxDurationSeconds ?? null,
                ticketMaxUses: parameters.ticketMaxUses ?? null,
                maxApiTokenDurationSeconds:
                    parameters.maxApiTokenDurationSeconds ?? null,
                webAuthMaxAgeSeconds: parameters.webAuthMaxAgeSeconds ?? null,
                webApprovalGracePeriodSeconds:
                    parameters.webApprovalGracePeriodSeconds ?? null,
                adminApprovalTimeoutSeconds:
                    parameters.adminApprovalTimeoutSeconds ?? null,
                adminApprovalGracePeriodSeconds:
                    parameters.adminApprovalGracePeriodSeconds ?? null,
                ...extraUpdate?.(),
            } as unknown as ParameterUpdate
            await api.updateParameters({ parameterUpdate })
            await onsaved?.()
            await reloadServerInfo()
        } catch (err) {
            updateError = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>{title}</h1>
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit global parameters."
    >
        {#if updateError}
            <Alert
                color="danger"
                dismissible
                onclose={() => {
                    updateError = undefined
                }}
                >{updateError}</Alert
            >
        {/if}
        <Loadable promise={initPromise}>
            {#if parameters}
                <form
                    bind:this={formEl}
                    oninput={refreshValidity}
                    onchange={refreshValidity}
                    onsubmit={e => {
                        e.preventDefault()
                        save()
                    }}
                >
                    <SectionedForm>
                        {@render children(parameters, refreshValidity)}
                    </SectionedForm>

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
        </Loadable>
    </PermissionGate>
</div>
