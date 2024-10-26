<script lang="ts">
import { timeAgo } from 'admin/lib/time'
interface Props {
    date: Date;
}

let { date }: Props = $props()
</script>

<span title={date.toLocaleString()}>{timeAgo(date)}</span>
