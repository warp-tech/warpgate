<script lang="ts">
    import { faPlus, faTimes } from '@fortawesome/free-solid-svg-icons'
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'

    // eslint-disable-next-line @typescript-eslint/no-type-alias
    type Headers = Record<string, string>

    interface Props {
        value?: Headers
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

    function serializeHeaders (headers: Headers | undefined): string {
        const entries = Object.entries(headers ?? {}).sort()
        return JSON.stringify(entries)
    }

    function syncRowsFromValue () {
        const serializedValue = serializeHeaders(value)
        if (serializedValue === lastSerializedValue) {
            return
        }

        lastSerializedValue = serializedValue
        headerRows = Object.entries(value ?? {}).map(([name, headerValue]) => ({
            id: nextHeaderId++,
            name,
            value: headerValue,
        }))
    }

    function syncValueFromRows () {
        const headers = Object.fromEntries(
            headerRows
                .map(({ name, value }) =>
                    [name.trim(), value] as const)
                .filter(([name]) => name.length > 0),
        )

        const nextValue = Object.keys(headers).length > 0 ? headers : undefined
        const serializedValue = serializeHeaders(nextValue)
        if (serializedValue === lastSerializedValue) {
            return
        }

        lastSerializedValue = serializedValue
        value = nextValue
    }

    function addHeaderRow () {
        headerRows = [
            ...headerRows,
            { id: nextHeaderId++, name: '', value: '' },
        ]
        syncValueFromRows()
    }

    function removeHeaderRow (id: number) {
        headerRows = headerRows.filter(header => header.id !== id)
        syncValueFromRows()
    }

    $effect(() => {
        syncRowsFromValue()
    })
</script>

<small class="form-text text-muted d-block mt-2 mb-3">
    Headers are added to all requests forwarded to the target. <a href="https://warpgate.null.page/targets/http/#built-in-headers" target="_blank" rel="noopener noreferrer">Some headers</a> are automatically set by Warpgate.
</small>

<FormGroup>
    {#each headerRows as header (header.id)}
        <div class="d-flex gap-3 mb-2">
            <input
                class="form-control flex-grow-1"
                type="text"
                placeholder="Header name"
                bind:value={header.name}
                oninput={syncValueFromRows}
            />
            <input
                class="form-control flex-grow-1"
                type="text"
                placeholder="Header value"
                bind:value={header.value}
                oninput={syncValueFromRows}
            />
            <button
                type="button"
                class="btn btn-link px-0"
                onclick={() => removeHeaderRow(header.id)}
                title="Remove"
            >
                <Fa icon={faTimes} />
            </button>
        </div>
    {/each}

    <button
        type="button"
        class="btn btn-secondary btn-sm d-flex align-items-center gap-2"
        onclick={addHeaderRow}
    >
        <Fa icon={faPlus} />
        Add custom header
    </button>
</FormGroup>
