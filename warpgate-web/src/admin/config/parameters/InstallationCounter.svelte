<script lang="ts">
    import { Button } from '@sveltestrap/sveltestrap'
    import AnalyticsConsentModal from 'admin/AnalyticsConsentModal.svelte'
    import { AnalyticsConsent, api, type ParameterValues } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import Loadable from 'common/Loadable.svelte'

    let parameters: ParameterValues | undefined = $state()
    let analyticsModalOpen = $state(false)

    const initPromise = load()

    async function load() {
        parameters = await api.getParameters({})
        return parameters
    }

    const analyticsLabel = $derived.by(() => {
        if (
            !parameters ||
            parameters.analyticsConsent !== AnalyticsConsent.On
        ) {
            return 'Off'
        }
        return parameters.analyticsNormal ? 'Normal' : 'Reduced'
    })
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>installation counter</h1>
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit global parameters."
    >
        <Loadable promise={initPromise}>
            <div class="d-flex align-items-center">
                <div>
                    Reporting:
                    <strong>{analyticsLabel}</strong>
                </div>
                <Button
                    class="ms-auto"
                    color="secondary"
                    onclick={() => (analyticsModalOpen = true)}
                >
                    Change
                </Button>
            </div>
        </Loadable>
    </PermissionGate>
</div>

{#if parameters}
    <AnalyticsConsentModal
        bind:isOpen={analyticsModalOpen}
        initialConsent={parameters.analyticsConsent}
        initialNormal={parameters.analyticsNormal}
        onsaved={load}
    />
{/if}
