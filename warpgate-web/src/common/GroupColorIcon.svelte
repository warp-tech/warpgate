<script lang="ts">
    import { faChevronRight, faCircle } from '@fortawesome/free-solid-svg-icons'
    import type { BootstrapThemeColor } from 'gateway/lib/api'
    import Fa from 'svelte-fa'

    const {
        color,
        collapsed = false,
    }: {
        color: BootstrapThemeColor | ''
        collapsed?: boolean
    } = $props()
</script>

<Fa
    fw
    icon={collapsed ? faChevronRight : faCircle}
    class="text-{color.toLowerCase()}"
/>
