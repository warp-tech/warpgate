<script lang="ts">
    import { faChevronRight } from '@fortawesome/free-solid-svg-icons'
    import type { BootstrapThemeColor } from 'gateway/lib/api'
    import Fa from 'svelte-fa'
    import GroupColorCircle from './GroupColorCircle.svelte'

    interface Props {
        name: string
        color: BootstrapThemeColor | ''
        count: number
        collapsed: boolean
        toggle: () => void
    }

    const { name, color, count, collapsed, toggle }: Props = $props()
</script>

<button
    type="button"
    class="group-header btn btn-link d-flex align-items-center gap-2 p-0 text-start mb-2 mt-4"
    aria-expanded={!collapsed}
    onclick={e => {
        e.preventDefault()
        toggle()
    }}
>
    <Fa fw icon={faChevronRight} rotate={collapsed ? 0 : 90} />
    <GroupColorCircle {color} />
    <span class="h5 mb-0">{name}</span>
    <small class="text-muted">{count}</small>
</button>

<style lang="scss">
    .group-header {
        color: inherit;
        text-decoration: none;

        &:hover,
        &:focus-visible {
            color: var(--bs-primary);
        }
    }
</style>
