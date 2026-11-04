<script lang="ts">
    import { faBriefcase } from '@fortawesome/free-solid-svg-icons'
    import { Tooltip } from '@sveltestrap/sveltestrap'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { uuid } from 'common/helpers'
    import Fa from 'svelte-fa'

    interface Props {
        provider?: string
        class?: string
        /// Offers to hand the row back to manual editing
        onRelease?: () => Promise<unknown>
    }

    let { provider, class: className = undefined, onRelease }: Props = $props()

    const GITOPS = '00000000-0000-0000-0000-000000000000'

    const id = uuid()
</script>

{#if provider}
    <div class={className} {id}>
        <Fa icon={faBriefcase} fw class="text-secondary" />
    </div>
    <Tooltip target={id} delay={500}>
        Managed by
        {#if provider === GITOPS}
            GitOps
        {:else}
            provider {provider}
        {/if}
    </Tooltip>
    {#if onRelease}
        <AsyncButton color="link" class="p-0" click={onRelease}>
            Release
        </AsyncButton>
    {/if}
{/if}
