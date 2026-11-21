<script lang="ts">
    import type { ParameterValues } from 'admin/lib/api'
    import Section from 'admin/lib/Section.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()
</script>

<ParametersForm title="network" bind:parameters>
    {#snippet children(parameters, refreshValidity)}
        <Section id="bandwidth-limit" title="Global bandwidth limit">
            <RateLimitInput
                id="rateLimitBytesPerSecond"
                bind:value={parameters.rateLimitBytesPerSecond}
                change={refreshValidity}
            />
        </Section>
    {/snippet}
</ParametersForm>
