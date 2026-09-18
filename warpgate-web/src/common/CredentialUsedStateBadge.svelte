<script lang="ts">
    /**
     * "Used recently" / "Not used recently" / "Never used".
     *
     * Behaviour preserved: the seven-day threshold, the three states, and the
     * added / last-used detail, which was a hover tooltip and stays one.
     *
     * The tooltip now wraps the badge instead of targeting it by a generated
     * id, which removes the uuid() and the element ref along with it.
     */
    import Badge from 'ui/Badge.svelte'
    import Tooltip from 'ui/Tooltip.svelte'

    interface DatedCredential {
        lastUsed?: Date
        dateAdded?: Date
    }

    interface Props {
        credential: DatedCredential
    }

    let { credential }: Props = $props()

    const LAST_USE_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000

    const state = $derived.by(() => {
        if (!credential.lastUsed) {
            return { tone: 'warning' as const, label: 'Never used' }
        }
        const stale =
            credential.lastUsed.getTime() < Date.now() - LAST_USE_THRESHOLD_MS
        return stale
            ? { tone: 'warning' as const, label: 'Not used recently' }
            : { tone: 'success' as const, label: 'Used recently' }
    })

    const detail = $derived(
        [
            credential.dateAdded
                ? `Added ${new Date(credential.dateAdded).toLocaleString()}`
                : null,
            credential.lastUsed
                ? `Last used ${new Date(credential.lastUsed).toLocaleString()}`
                : null,
        ]
            .filter(Boolean)
            .join(' · '),
    )
</script>

{#if detail}
    <Tooltip text={detail} delay={250}>
        <Badge tone={state.tone}>{state.label}</Badge>
    </Tooltip>
{:else}
    <Badge tone={state.tone}>{state.label}</Badge>
{/if}
