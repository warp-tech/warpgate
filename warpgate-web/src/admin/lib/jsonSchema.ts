/** A JSON Schema (draft 2020-12) node, as far as the viewer reads it */
export interface JsonSchema {
    $ref?: string
    title?: string
    description?: string
    type?: string | string[]
    properties?: Record<string, JsonSchema>
    required?: string[]
    oneOf?: JsonSchema[]
    anyOf?: JsonSchema[]
    enum?: unknown[]
    const?: unknown
    default?: unknown
    format?: string
    minimum?: number
    maximum?: number
    items?: JsonSchema
    additionalProperties?: boolean | JsonSchema
    [keyword: string]: unknown
}

/** Keywords the viewer renders itself. `extras` lists every other one, so none is hidden. */
const RENDERED = new Set([
    '$schema',
    '$defs',
    'title',
    'description',
    'type',
    'properties',
    'required',
    'oneOf',
    'anyOf',
    'enum',
    'const',
    'default',
    'format',
    'minimum',
    'maximum',
    'items',
    'additionalProperties',
    // `false` on nearly every object, and says nothing about the listed keys
    'unevaluatedProperties',
])

const MAX_REF_HOPS = 32

function lookup(root: JsonSchema, ref: string): JsonSchema {
    let node: unknown = ref.startsWith('#') ? root : undefined
    for (const part of ref.slice(1).split('/').filter(Boolean)) {
        const key = part.replaceAll('~1', '/').replaceAll('~0', '~')
        node = (node as Record<string, unknown> | undefined)?.[key]
    }
    return (node as JsonSchema | undefined) ?? { 'unresolved $ref': ref }
}

function merge(base: JsonSchema, over: JsonSchema): JsonSchema {
    const merged: JsonSchema = { ...base, ...over }
    if (base.properties || over.properties) {
        // A union's tag sits next to the `$ref`, and reads best first
        merged.properties = { ...over.properties, ...base.properties }
    }
    if (base.required || over.required) {
        merged.required = [
            ...new Set([...(base.required ?? []), ...(over.required ?? [])]),
        ]
    }
    return merged
}

function typesOf(node: JsonSchema): string[] {
    return [node.type ?? []].flat()
}

/**
 * Follows `$ref`s and folds "X or null" into X's type. In 2020-12 the keywords
 * next to a `$ref` apply together with its target, so both are merged.
 */
export function resolve(schema: JsonSchema, root: JsonSchema): JsonSchema {
    let node = schema
    for (let hops = 0; node.$ref !== undefined && hops < MAX_REF_HOPS; hops++) {
        const { $ref, ...siblings } = node
        node = merge(lookup(root, $ref), siblings)
    }

    const variants = node.anyOf ?? node.oneOf
    const [first, second] = variants ?? []
    if (variants?.length === 2 && first && second) {
        const other = first.type === 'null' ? second : first
        if ((first.type === 'null') !== (second.type === 'null')) {
            const { anyOf: _, oneOf: __, ...rest } = node
            const inner = resolve(other, root)
            node = { ...merge(inner, rest), type: [...typesOf(inner), 'null'] }
        }
    }
    return node
}

export function variantsOf(
    node: JsonSchema,
    root: JsonSchema,
): JsonSchema[] | undefined {
    return (node.oneOf ?? node.anyOf)?.map(variant => resolve(variant, root))
}

/** A union variant is told apart by its constant tag, or by the one key it holds */
export function variantLabel(variant: JsonSchema, root: JsonSchema): string {
    const properties = Object.entries(variant.properties ?? {})
    const tag = properties.find(([, property]) => property.const !== undefined)
    if (tag) {
        return String(tag[1].const)
    }
    const [only] = properties
    if (properties.length === 1 && only) {
        return only[0]
    }
    return variant.title ?? typeLabel(variant, root)
}

export function typeLabel(node: JsonSchema, root: JsonSchema): string {
    const types = typesOf(node)
    const nullable = types.length > 1 && types.includes('null')
    let label: string
    if (node.const !== undefined) {
        label = JSON.stringify(node.const)
    } else if (node.enum) {
        label = node.enum.map(value => JSON.stringify(value)).join(' | ')
    } else if (node.oneOf ?? node.anyOf) {
        label = 'one of'
    } else {
        label =
            types
                .filter(type => !nullable || type !== 'null')
                .map(type => {
                    if (type === 'array' && node.items) {
                        return `array of ${typeLabel(resolve(node.items, root), root)}`
                    }
                    if (
                        type === 'object' &&
                        typeof node.additionalProperties === 'object'
                    ) {
                        return `map of ${typeLabel(resolve(node.additionalProperties, root), root)}`
                    }
                    return node.format ? `${type} (${node.format})` : type
                })
                .join(' | ') || 'any'
    }
    return nullable ? `${label} | null` : label
}

export function range(node: JsonSchema): string | undefined {
    const { minimum, maximum } = node
    if (minimum !== undefined && maximum !== undefined) {
        return `${minimum}–${maximum}`
    }
    if (minimum !== undefined) {
        return `≥ ${minimum}`
    }
    if (maximum !== undefined) {
        return `≤ ${maximum}`
    }
    return undefined
}

/** Keywords the viewer has no rendering for, as `keyword: value` */
export function extras(node: JsonSchema): string[] {
    return Object.entries(node)
        .filter(([keyword]) => !RENDERED.has(keyword))
        .map(([keyword, value]) => `${keyword}: ${JSON.stringify(value)}`)
}

/** Whether there is anything to show under a node besides its own row */
export function hasChildren(node: JsonSchema, root: JsonSchema): boolean {
    if (node.oneOf ?? node.anyOf) {
        return true
    }
    if (Object.keys(node.properties ?? {}).length) {
        return true
    }
    const inner =
        node.items ??
        (typeof node.additionalProperties === 'object'
            ? node.additionalProperties
            : undefined)
    return inner !== undefined && hasChildren(resolve(inner, root), root)
}
