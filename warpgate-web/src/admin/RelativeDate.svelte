<script lang="ts">
import { timeAgo } from 'admin/lib/time'
export let date: any
</script>

<span title={date}>{timeAgo(date)}</span>
