<script lang="ts">
    import {
        faChevronDown,
        faChevronRight,
    } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import {
        extras,
        hasChildren,
        type JsonSchema,
        range,
        resolve,
        typeLabel,
        variantLabel,
        variantsOf,
    } from './jsonSchema'
    import Self from './SchemaNode.svelte'

    interface Props {
        schema: JsonSchema
        /** The document that `$ref`s point into */
        root: JsonSchema
        depth?: number
    }

    const { schema, root, depth = 0 }: Props = $props()

    const node = $derived(resolve(schema, root))
    const variants = $derived(variantsOf(node, root))
    const properties = $derived(Object.entries(node.properties ?? {}))
    const inner = $derived(
        node.items ??
            (typeof node.additionalProperties === 'object'
                ? node.additionalProperties
                : undefined),
    )

    let selected = $state(0)
    // Unset keys follow the default: open near the top, or when there is nothing else to see
    let toggled: Record<string, boolean> = $state({})

    function isOpen(name: string): boolean {
        return toggled[name] ?? (depth < 1 || properties.length === 1)
    }
</script>

{#snippet prose(text: string)}
    {#each text.split('`') as part, i (i)}
        {#if i % 2}
            <code>{part}</code>
        {:else}
            {part}
        {/if}
    {/each}
{/snippet}

{#if variants}
    {@const variant = variants[selected]}
    <ul class="nav nav-pills mb-2">
        {#each variants as option, i (i)}
            <li class="nav-item">
                <button
                    type="button"
                    class="nav-link py-1"
                    class:active={i === selected}
                    onclick={() => (selected = i)}
                >
                    {variantLabel(option, root)}
                </button>
            </li>
        {/each}
    </ul>
    {#if variant}
        {#if variant.description}
            <div class="text-muted small mb-2">
                {@render prose(variant.description)}
            </div>
        {/if}
        {#key selected}
            <Self schema={variant} {root} {depth} />
        {/key}
    {/if}
{:else if properties.length}
    {#each properties as [name, property] (name)}
        {@const child = resolve(property, root)}
        {@const expandable = hasChildren(child, root)}
        {@const open = expandable && isOpen(name)}
        <div class="py-1">
            <div class="d-flex align-items-baseline flex-wrap column-gap-2">
                {#if expandable}
                    <button
                        type="button"
                        class="btn btn-link p-0 d-flex align-items-baseline gap-2 text-decoration-none"
                        aria-expanded={open}
                        onclick={() => (toggled[name] = !open)}
                    >
                        <Fa
                            icon={open ? faChevronDown : faChevronRight}
                            fw
                            size="xs"
                        />
                        <code>{name}</code>
                    </button>
                {:else}
                    <span class="d-flex align-items-baseline gap-2">
                        <Fa
                            icon={faChevronRight}
                            fw
                            size="xs"
                            class="invisible"
                        />
                        <code>{name}</code>
                    </span>
                {/if}
                <span class="text-muted small">{typeLabel(child, root)}</span>
                {#if node.required?.includes(name)}
                    <span class="text-danger small">required</span>
                {/if}
                {#if child.default !== undefined && child.default !== null}
                    <span class="text-muted small">
                        default <code>{JSON.stringify(child.default)}</code>
                    </span>
                {/if}
                {#if range(child)}
                    <span class="text-muted small">{range(child)}</span>
                {/if}
                {#each extras(child) as extra (extra)}
                    <code class="small">{extra}</code>
                {/each}
            </div>
            {#if child.description}
                <div class="text-muted small ms-4">
                    {@render prose(child.description)}
                </div>
            {/if}
            {#if open}
                <div class="ms-2 mt-1 ps-3 border-start">
                    <Self schema={child} {root} depth={depth + 1} />
                </div>
            {/if}
        </div>
    {/each}
{:else if inner}
    <Self schema={inner} {root} {depth} />
{/if}
