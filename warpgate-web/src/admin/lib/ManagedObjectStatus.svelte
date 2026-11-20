<script lang="ts">
    import { faBriefcase } from '@fortawesome/free-solid-svg-icons'
    import {
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
    } from '@sveltestrap/sveltestrap'
    import type { Provider } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import Fa from 'svelte-fa'

    interface Props {
        provider?: Provider
        class?: string
        /** Release and reloads object in parent view */
        release: () => Promise<unknown>
    }

    let { provider, class: className, release }: Props = $props()

    let error: string | undefined = $state()

    async function confirmRelease() {
        if (
            !confirm(
                'Release this object to make it editable? If the GitOps source still contains it, future syncs will fail until it is removed or marked with `adopt_existing` in GitOps.',
            )
        ) {
            return
        }
        error = undefined
        try {
            await release()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
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
            Managed by {provider.label}
        </DropdownToggle>
        <DropdownMenu end>
            <DropdownItem
                disabled={!$adminPermissions.configEdit}
                onclick={confirmRelease}
            >
                Release
            </DropdownItem>
        </DropdownMenu>
    </Dropdown>
{/if}
{#if error}
    <div class="text-danger small">{error}</div>
{/if}
