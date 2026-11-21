<script lang="ts">
    import { faBriefcase } from '@fortawesome/free-solid-svg-icons'
    import { Tooltip } from '@sveltestrap/sveltestrap'
    import type { Provider } from 'admin/lib/api'
    import Fa from 'svelte-fa'

    interface Props {
        provider?: Provider
        class?: string
    }

    let { provider, class: className }: Props = $props()

    let wrapper: HTMLElement | null = $state(null)
    let label = $derived(provider ? `Managed by ${provider.label}` : '')
</script>

{#if provider}
    <div class={className} bind:this={wrapper} role="img" aria-label={label}>
        <Fa icon={faBriefcase} fw class="text-secondary" />
    </div>
    <Tooltip target={wrapper} delay={500} placement="top">{label}</Tooltip>
{/if}
