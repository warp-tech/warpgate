<script lang="ts">
    /**
     * Custom request headers forwarded to an HTTP target.
     *
     * The sync logic is preserved verbatim. It looks over-engineered and is
     * not: `value` is a Record, `headerRows` is an ordered list with stable
     * ids, and each has to follow the other. Comparing a sorted serialisation
     * before writing is what stops the two effects ping-ponging, and dropping
     * it would produce an infinite update loop rather than a visible bug.
     *
     * Rows with a blank name are filtered out of `value` but kept in the list,
     * so a half-typed row does not vanish under the cursor.
     */
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'

    type Headers = Record<string, string>

    interface Props {
        value: Headers
    }

    interface HeaderRow {
        id: number
        name: string
        value: string
    }

    let { value = $bindable() }: Props = $props()

    let nextHeaderId = 1
    let headerRows: HeaderRow[] = $state([])
    let lastSerializedValue = $state('')

    function serializeHeaders(headers: Headers): string {
        return JSON.stringify(Object.entries(headers).sort())
    }

    function syncRowsFromValue() {
        const serializedValue = serializeHeaders(value)
        if (serializedValue === lastSerializedValue) {
            return
        }

        lastSerializedValue = serializedValue
        headerRows = Object.entries(value).map(([name, headerValue]) => ({
            id: nextHeaderId++,
            name,
            value: headerValue,
        }))
    }

    function syncValueFromRows() {
        const headers = Object.fromEntries(
            headerRows
                .map(({ name, value: v }) => [name.trim(), v] as const)
                .filter(([name]) => name.length > 0),
        )

        const serializedValue = serializeHeaders(headers)
        if (serializedValue === lastSerializedValue) {
            return
        }

        lastSerializedValue = serializedValue
        value = headers
    }

    function addHeaderRow() {
        headerRows = [
            ...headerRows,
            { id: nextHeaderId++, name: '', value: '' },
        ]
        syncValueFromRows()
    }

    function removeHeaderRow(id: number) {
        headerRows = headerRows.filter(header => header.id !== id)
        syncValueFromRows()
    }

    $effect(() => {
        syncRowsFromValue()
    })
</script>

<p class="intro">
    Headers are added to every request forwarded to the target.
    <a
        href="https://warpgate.null.page/targets/http/#built-in-headers"
        target="_blank"
        rel="noopener noreferrer"
    >
        Some headers
    </a>
    are set by Warpgate automatically.
</p>

<div class="rows">
    {#each headerRows as header (header.id)}
        <div class="header-row">
            <Input
                label="Header name"
                labelHidden
                placeholder="Header name"
                mono
                bind:value={header.name}
                oninput={syncValueFromRows}
            />
            <Input
                label="Header value"
                labelHidden
                placeholder="Header value"
                mono
                bind:value={header.value}
                oninput={syncValueFromRows}
            />
            <Button
                variant="ghost"
                size="compact"
                label={header.name
                    ? `Remove header ${header.name}`
                    : 'Remove this header'}
                onclick={() => removeHeaderRow(header.id)}
            >
                <svg
                    viewBox="0 0 16 16"
                    width="12"
                    height="12"
                    aria-hidden="true"
                >
                    <path
                        d="M4 4l8 8M12 4l-8 8"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.75"
                        stroke-linecap="round"
                    />
                </svg>
            </Button>
        </div>
    {/each}
</div>

<Button size="compact" onclick={addHeaderRow}>Add custom header</Button>

<style>
    .intro {
        margin: 0 0 var(--wg-space-md);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
    }

    .intro a {
        color: var(--wg-primary);
    }

    .intro a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
        border-radius: var(--wg-radius-sm);
    }

    .rows {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        margin-bottom: var(--wg-space-md);
    }

    .header-row {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .header-row > :global(*:not(:last-child)) {
        flex: 1 1 0;
        min-width: 0;
    }
</style>
