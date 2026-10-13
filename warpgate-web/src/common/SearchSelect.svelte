<script lang="ts" generics="T">
    // A searchable replacement for a <select>, for choosing from more options
    // than can be loaded at once: `load` is asked for one page of matches as
    // the user types. Renders a bare .form-control, so that it can sit in a
    // floating-label FormGroup like a regular input.

    interface Props {
        value?: T
        load: (search: string) => Promise<{ items: T[]; total: number }>
        itemLabel: (_: T) => string
        itemKey: (_: T) => unknown
        // When set, offered first, and selects nothing
        emptyOption?: string
        placeholder?: string
        required?: boolean
        onchange?: (_: T | undefined) => void
    }

    let {
        value = $bindable(),
        load,
        itemLabel,
        itemKey,
        emptyOption,
        placeholder = 'Search...',
        required = false,
        onchange,
    }: Props = $props()

    type Option = { item: T | undefined }

    const labelOf = (item: T | undefined) =>
        item === undefined ? (emptyOption ?? '') : itemLabel(item)

    let text = $state('')
    let open = $state(false)
    let focused = $state(false)
    let results = $state.raw<T[]>([])
    let total = $state(0)
    let active = $state(0)
    let loading = $state(false)
    let error = $state(false)
    let request = 0
    const uid = $props.id()
    const listboxId = `search-select-${uid}`
    let debounce: ReturnType<typeof setTimeout> | undefined

    const options: Option[] = $derived([
        ...(emptyOption !== undefined && !text ? [{ item: undefined }] : []),
        ...results.map(item => ({ item })),
    ])

    // Reflect selections made from outside, but not while the user is typing
    $effect(() => {
        const label = labelOf(value)
        if (!focused) {
            text = label
        }
    })

    async function search(query: string) {
        const current = ++request
        loading = true
        try {
            const response = await load(query)
            if (current === request) {
                results = response.items
                total = response.total
                active = 0
                error = false
            }
        } catch {
            if (current === request) {
                results = []
                total = 0
                error = true
            }
        } finally {
            if (current === request) {
                loading = false
            }
        }
    }

    function scheduleSearch() {
        clearTimeout(debounce)
        debounce = setTimeout(() => search(text), 200)
    }

    function select(option: Option) {
        value = option.item
        text = labelOf(option.item)
        open = false
        onchange?.(option.item)
    }

    function onfocus(e: FocusEvent) {
        focused = true
        open = true
        ;(e.currentTarget as HTMLInputElement).select()
        search('')
    }

    function onblur() {
        focused = false
        open = false
        clearTimeout(debounce)
        // Typing without picking anything keeps the previous choice
        text = labelOf(value)
    }

    function onkeydown(e: KeyboardEvent) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault()
            open = true
            if (options.length) {
                const step = e.key === 'ArrowDown' ? 1 : -1
                active = (active + step + options.length) % options.length
            }
        } else if (e.key === 'Enter' && open) {
            e.preventDefault()
            const option = options[active]
            if (option) {
                select(option)
            }
        } else if (e.key === 'Escape' && open) {
            e.preventDefault()
            open = false
        }
    }

    $effect(() => () => clearTimeout(debounce))
</script>

<input
    class="form-control"
    type="text"
    autocomplete="off"
    role="combobox"
    aria-controls={listboxId}
    aria-expanded={open}
    aria-autocomplete="list"
    {placeholder}
    required={required && value === undefined}
    bind:value={text}
    oninput={() => {
        open = true
        scheduleSearch()
    }}
    {onfocus}
    {onblur}
    {onkeydown}
>
{#if open}
    <div class="dropdown-menu show w-100" role="listbox" id={listboxId}>
        {#each options as option, i (option.item === undefined ? undefined : itemKey(option.item))}
            <button
                type="button"
                class="dropdown-item"
                class:active={i === active}
                role="option"
                aria-selected={i === active}
                tabindex="-1"
                onmousedown={e => {
                    // Keep focus in the input until the choice is made
                    e.preventDefault()
                }}
                onclick={() => select(option)}
            >
                {#if option.item === undefined}
                    <em>{emptyOption}</em>
                {:else}
                    {itemLabel(option.item)}
                {/if}
            </button>
        {/each}
        {#if error}
            <div class="dropdown-item-text text-danger">Could not load</div>
        {:else if !loading && !results.length}
            <div class="dropdown-item-text text-muted">Nothing found</div>
        {:else if total > results.length}
            <div class="dropdown-item-text text-muted small">
                {total - results.length}
                more - keep typing to narrow down
            </div>
        {/if}
    </div>
{/if}

<style lang="scss">
    .dropdown-menu {
        max-height: 20rem;
        overflow-y: auto;
    }
</style>
