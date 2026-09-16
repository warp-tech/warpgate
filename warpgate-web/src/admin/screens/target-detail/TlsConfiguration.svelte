<script lang="ts">
    /**
     * TLS mode and certificate verification.
     *
     * Shared by HTTP (4c), MySQL/PostgreSQL and Kubernetes (4f) — migrated
     * once here, the same shape as SectionedForm in 4a. 4f's diff is
     * correspondingly small because this already exists by then.
     *
     * Two changes:
     *
     * 1. Selecting "Disabled" raises a warning Callout beneath the select
     *    rather than styling the option itself. A red option in a dropdown is
     *    invisible once the dropdown closes — which is exactly when it
     *    matters, because the operator is now looking at a form that says
     *    "Disabled" in ordinary text. The callout persists while the choice
     *    does. Verification being off gets a quieter callout: weaker, but
     *    still a downgrade from the default.
     *
     * 2. "Verify certificate" becomes a Checkbox. It binds into `value` and is
     *    written when the parent form saves — a deferred write.
     */
    import { type Tls, TlsMode } from 'admin/lib/api'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        value: Tls
        /** Names the thing being connected to, for the warning copy. */
        subject?: string
        class?: string
    }

    let {
        value = $bindable(),
        subject = 'this target',
        class: className = '',
    }: Props = $props()

    const MODES = [
        { value: TlsMode.Required, label: 'Required' },
        { value: TlsMode.Preferred, label: 'Preferred' },
        { value: TlsMode.Disabled, label: 'Disabled' },
    ]

    const disabled = $derived(value.mode === TlsMode.Disabled)
    const unverified = $derived(!disabled && !value.verify)
</script>

<div class="tls {className}">
    <div class="tls-row">
        <Select label="TLS mode" options={MODES} bind:value={value.mode} />
        {#if !disabled}
            <Checkbox label="Verify certificate" bind:checked={value.verify} />
        {/if}
    </div>

    {#if disabled}
        <Callout
            tone="warning"
            title="Traffic to {subject} will not be encrypted"
        >
            Warpgate will connect in plaintext. Anything on the path between
            Warpgate and the target — including credentials it forwards — is
            readable by anything that can see that network segment. Use this
            only on a segment you control end to end.
        </Callout>
    {:else if unverified}
        <Callout tone="warning" title="Certificate will not be verified">
            Warpgate will encrypt the connection but accept any certificate, so
            it cannot tell {subject} from something impersonating it. If the
            target uses a self-signed certificate, trust it explicitly rather
            than turning verification off.
        </Callout>
    {/if}
</div>

<style>
    .tls {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-lg);
    }

    .tls-row {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-lg);
    }

    .tls-row > :global(*:first-child) {
        flex: 1 1 14rem;
        min-width: 0;
    }
</style>
