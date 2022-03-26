<script lang="ts">
import { timeAgo } from 'lib/time'
export let date: any
</script>

<span title={date}>{timeAgo(date)}</span>
