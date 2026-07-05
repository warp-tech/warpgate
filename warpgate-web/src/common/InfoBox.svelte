<script lang="ts">
    import { faInfoCircle, faTriangleExclamation, type IconDefinition } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import type { Snippet } from 'svelte'

    interface Props {
        class?: string,
        children: Snippet,
        variant?: 'info' | 'warning',
        icon?: IconDefinition,
    }

    // eslint-disable-next-line svelte/no-unused-props
    let {
        children,
        'class': className = 'mt-3 mb-4',
        variant = 'info',
        icon,
    }: Props = $props()

    let iconToUse = $derived.by(() => icon ?? (variant === 'warning' ? faTriangleExclamation : faInfoCircle))
    let variantClass = $derived.by(() => variant === 'warning' ? 'text-warning' : 'text-muted')
</script>

<div class="d-flex gap-2 align-items-center {variantClass} {className}">
    <Fa icon={iconToUse} />
    <small>
        {@render children()}
    </small>
</div>

<style>
    div {
        line-height: 1.2;
    }
</style>
