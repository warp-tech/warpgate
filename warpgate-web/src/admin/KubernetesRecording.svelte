<script lang="ts">
    import type { KubernetesRecordingItem } from './lib/api'
    interface Props {
        items: KubernetesRecordingItem[]
    }

    let { items }: Props = $props()
</script>

{#each items as item (item)}
    <div class="item">
        <strong>{new Date(item.time).toLocaleString()}:</strong> {item.responseStatus} {item.requestMethod} {item.requestPath}
        <code>{item.requestBody}</code>
        <!-- TODO -->
    </div>
{/each}
