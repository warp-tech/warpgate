<script lang="ts">
    import { Badge } from '@sveltestrap/sveltestrap'
    import type { Recording } from 'admin/lib/api'
    import { onMount } from 'svelte'
    import { firstBy } from 'thenby'

    interface Props {
        recording: Recording
    }

    let { recording }: Props = $props()

    // Parsed from the raw NDJSON recording (served like every other recording).
    // The stored bodies are JSON payloads: the request base64-encoded, the
    // response a raw byte array; both are decoded here for display.
    interface KubernetesItem {
        timestamp: Date
        requestMethod: string
        requestPath: string
        responseStatus?: number
        requestBody: { kind?: string } | null
        responseBody: {
            kind?: string
            columnDefinitions?: { name: string }[]
            items?: {
                metadata: {
                    name: string
                    namespace: string
                }
            }[]
            rows?: { cells: unknown[] }[]
        } | null
    }

    let items: KubernetesItem[] = $state([])

    function decodeJson<T>(bytes: Uint8Array): T | null {
        try {
            return JSON.parse(new TextDecoder().decode(bytes))
        } catch {
            return null
        }
    }

    onMount(async () => {
        const url = `/@warpgate/admin/api/recordings/${recording.id}/data`
        const text = await fetch(url).then(r => r.text())
        const parsed: KubernetesItem[] = []
        for (const line of text.split('\n')) {
            if (!line.trim()) {
                continue
            }
            const raw = JSON.parse(line)
            const requestBytes = Uint8Array.from(atob(raw.request_body), c =>
                c.charCodeAt(0),
            )
            const responseBytes = raw.response_body
                ? Uint8Array.from(raw.response_body)
                : new Uint8Array()
            parsed.push({
                timestamp: new Date(raw.timestamp),
                requestMethod: raw.request_method,
                requestPath: raw.request_path,
                responseStatus: raw.response_status ?? undefined,
                requestBody: decodeJson(requestBytes),
                responseBody: decodeJson(responseBytes),
            })
        }
        items = parsed
    })

    const sortedItems = $derived(
        items
            .slice()
            .sort(firstBy(x => x.timestamp))
            .reverse(),
    )

    function isSuccessStatus(status: number) {
        return status >= 200 && status < 300
    }
</script>

{#each sortedItems as item (item)}
    <div class="item">
        <div class="d-flex align-items-center gap-2">
            {#if item.responseStatus}
                <Badge
                    color={isSuccessStatus(item.responseStatus) ? 'success' : 'danger'}
                >
                    {item.responseStatus}
                </Badge>
            {/if}
            {#if item.requestMethod === 'GET'}
                <Badge color="success">
                    {item.requestMethod}
                </Badge>
            {:else}
                <Badge color="warning">
                    {item.requestMethod}
                </Badge>
            {/if}
            <code>{item.requestPath}</code>
            <div class="text-muted ms-auto">
                {item.timestamp.toLocaleString()}
            </div>
        </div>

        <div class="contents">
            {#if item.requestBody}
                <details>
                    <summary>Request body ({item.requestBody.kind})</summary>
                    <pre>{JSON.stringify(item.requestBody, undefined, 2)}</pre>
                </details>
            {/if}

            {#if item.responseBody}
                <details>
                    <summary>Response body ({item.responseBody.kind})</summary>
                    {#if item.responseBody.kind === 'Table'}
                        <table class="table">
                            <thead>
                                <tr>
                                    {#each item.responseBody.columnDefinitions as colDef (colDef)}
                                        <th>{colDef.name}</th>
                                    {/each}
                                </tr>
                            </thead>
                            <tbody>
                                {#each item.responseBody.rows as row (row)}
                                    <tr>
                                        {#each row.cells as cell}
                                            <td>{cell}</td>
                                        {/each}
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    {:else if item.responseBody.kind?.endsWith('List')}
                        {#if item.responseBody.items?.length === 0}
                            <table class="table">
                                <tbody>
                                    <tr>
                                        <td>
                                            <div class="text-muted">
                                                No items
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        {:else}
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Namespace</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {#each item.responseBody.items as row (row)}
                                        <tr>
                                            <td>{row.metadata.name}</td>
                                            <td>{row.metadata.namespace}</td>
                                            <td>
                                                <details>
                                                    <summary>
                                                        Full entry
                                                    </summary>
                                                    <pre
                                                    >{JSON.stringify(row, undefined, 2)}</pre>
                                                </details>
                                            </td>
                                        </tr>
                                    {/each}
                                </tbody>
                            </table>
                        {/if}
                    {:else}
                        <pre
                        >{JSON.stringify(item.responseBody, undefined, 2)}</pre>
                    {/if}
                </details>
            {/if}
        </div>
        <!-- TODO -->
    </div>
{/each}

<style lang="scss">
    .item {
        .contents {
            margin-left: 7rem;
            margin-bottom: 1rem;
        }
    }
</style>
