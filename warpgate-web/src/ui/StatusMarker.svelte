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
            ended: Object.freeze({
                shape: 'dot',
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

    .wg-marker {
        flex: none;
        width: var(--wg-marker-size);
        height: var(--wg-marker-size);
    }

    .wg-marker-dot {
        background: var(--marker);
        border-radius: var(--wg-radius-full);
    }

    .wg-marker-ring {
        width: 7px;
        height: 7px;
        border: 1.5px solid var(--marker);
        border-radius: var(--wg-radius-full);
    }

    .wg-marker-square {
        background: var(--marker);
    }

    .wg-marker-triangle {
        width: 0;
        height: 0;
        border-left: 3.5px solid transparent;
        border-right: 3.5px solid transparent;
        border-bottom: 6px solid var(--marker);
    }

    .wg-marker-diamond {
        background: var(--marker);
        transform: rotate(45deg);
    }

    .wg-marker-pulse {
        animation: wg-pulse 2s ease-in-out infinite;
    }

    @keyframes wg-pulse {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.4;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-marker-pulse {
            animation: none;
        }
    }
</style>
