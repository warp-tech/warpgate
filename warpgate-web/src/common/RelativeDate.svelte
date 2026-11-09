<script lang="ts">
    import { Tooltip } from '@sveltestrap/sveltestrap'
    import { timeAgo } from 'admin/lib/time'

    interface Props {
        date: Date
    }

    let { date }: Props = $props()
    let span = $state<HTMLElement>()
</script>

<span bind:this={span}>{timeAgo(date)}</span>

<Tooltip target={span} placement="top" delay="500">
    {date.toLocaleString()}
</Tooltip>
