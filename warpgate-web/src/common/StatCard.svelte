<script lang="ts">
    interface Props {
        value: string | number,
        label: string,
        color?: string,
        class?: string,
    }

    // eslint-disable-next-line svelte/no-unused-props
    let {
        value,
        label,
        color,
        'class': className = '',
    }: Props = $props()
</script>

<div class="stat-card {color ? `text-${color}` : ''} {className}">
    <div class="stat-value">{value}</div>
    <div class="stat-label">{label}</div>
</div>

<style lang="scss">
    .stat-card {
        min-width: 120px;
        padding: .5rem;
    }

    .stat-value {
        font-size: 1.75rem;
        font-weight: bold;
        line-height: 1;
    }

    .stat-label {
        font-size: 0.75rem;
        color: var(--bs-secondary);
        margin-top: 0.25rem;
    }
</style>
