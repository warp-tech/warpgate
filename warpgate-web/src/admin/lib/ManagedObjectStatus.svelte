<script lang="ts">
    import { faBriefcase } from '@fortawesome/free-solid-svg-icons'
    import {
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import { providerLabel } from 'admin/lib/providers'
    import Fa from 'svelte-fa'

    interface Props {
        provider?: string
        class?: string
        onRelease?: () => Promise<unknown>
    }

    let { provider, class: className, onRelease }: Props = $props()
</script>

{#if provider}
    <Dropdown class={className}>
        <DropdownToggle
            color="info"
            size="sm"
            class="d-inline-flex gap-2 align-items-center"
            caret
        >
            <Fa icon={faBriefcase} fw class="text-secondary" />
            Managed by {providerLabel(provider)}
        </DropdownToggle>
        <DropdownMenu end>
            <DropdownItem disabled={!onRelease} onclick={onRelease}>
                Release
            </DropdownItem>
        </DropdownMenu>
    </Dropdown>
{/if}
