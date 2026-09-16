<script lang="ts" module>
    /**
     * The status convention for every table in the product.
     *
     * DESIGN.md's rule is that state is always geometry + label + colour, never
     * colour alone. This component enforces that structurally rather than by
     * convention: there is **no `colour` prop and no `shape` prop**. A call site
     * picks a `kind` from a closed set, and the geometry and colour come with it.
     *
     * That is deliberate. A component that accepted `colour` would eventually be
     * handed one without a shape — not out of carelessness, but because at 3am
     * the quickest way to show "this row is bad" is to make it red. Removing the
     * prop removes the option.
     *
     * `label` is customisable because timestamps belong in it ("Ended 12:04:31"),
     * but it cannot be omitted: every kind carries a default, and the label always
     * renders as visible text. The text is the accessible name, so the shape is
     * aria-hidden.
     *
     * Adding a kind means adding a row here, which is the review point.
     */

    export type StatusKind =
        | 'live'
        | 'online'
        | 'blocked'
        | 'ended'
        | 'failed'
        | 'pending'

    type Shape = 'dot' | 'ring' | 'square' | 'triangle' | 'diamond'

    interface StatusSpec {
        shape: Shape
        token: string
        defaultLabel: string
        /** Only `live` pulses; a steady product is a quiet one. */
        pulse?: boolean
    }

    export const STATUS: Readonly<Record<StatusKind, Readonly<StatusSpec>>> =
        Object.freeze({
            live: Object.freeze({
                shape: 'dot',
                token: '--wg-state-live',
                defaultLabel: 'Live',
                pulse: true,
            }),
            online: Object.freeze({
                shape: 'ring',
                token: '--wg-state-online',
                defaultLabel: 'Online',
            }),
            blocked: Object.freeze({
                shape: 'square',
                token: '--wg-state-blocked',
                defaultLabel: 'Blocked',
            }),
            /**
             * Hollow, not filled — a divergence from DESIGN.md, which draws
             * both `live` and `ended` as solid 6px circles separated only by
             * colour and the pulse. Those are the two most common states in
             * the product and they sit in the same column on adjacent rows
             * constantly, so the geometry was carrying nothing exactly where
             * it is needed most.
             *
             * Sharing the ring with `online` is safe: a session's state and a
             * target's health never appear in the same column.
             */
            ended: Object.freeze({
                shape: 'ring',
                token: '--wg-state-ended',
                defaultLabel: 'Ended',
            }),
            failed: Object.freeze({
                shape: 'triangle',
                token: '--wg-state-failed',
                defaultLabel: 'Failed',
            }),
            pending: Object.freeze({
                shape: 'diamond',
                token: '--wg-state-pending',
                defaultLabel: 'Pending',
            }),
        })
</script>

<script lang="ts">
    interface Props {
        kind: StatusKind
        /** Defaults to the kind's own label. Cannot be blanked. */
        label?: string
        /** Drops the surrounding chip, for use inside a dense table cell. */
        bare?: boolean
    }

    let { kind, label, bare = false }: Props = $props()

    // Geometry is shared with Callout and ToastHost so one semantic has one
    // shape everywhere. See ui/markers.css.
    import './markers.css'

    const spec = $derived(STATUS[kind])
    const text = $derived(label?.trim() || spec.defaultLabel)
</script>

<span class="wg-status" class:wg-status-bare={bare}>
    <span
        class="wg-marker wg-marker-{spec.shape}"
        class:wg-marker-pulse={spec.pulse}
        style="--marker: var({spec.token})"
        aria-hidden="true"
    ></span>
    <span class="wg-status-label">{text}</span>
</span>

<style>
    .wg-status {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-badge-height);
        padding: 0 var(--wg-badge-padding-x);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-surface-container);
        font: var(--wg-text-label-sm);
        color: var(--wg-text);
        white-space: nowrap;
    }

    .wg-status-bare {
        border: 0;
        background: none;
        padding: 0;
        height: auto;
    }
</style>
