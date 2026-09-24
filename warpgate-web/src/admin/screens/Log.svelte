<script lang="ts">
    /**
     * Audit log — screen 10.
     *
     * ── Enumeration of admin/Log.svelte, asserted present ────────────────
     * The four titles (plain log, user, access role, admin role, each showing
     * the id); the "Audit log only" switch, shown only when no filterKind is
     * set, persisted through common/autosave under 'log.target'; the derived
     * filters object with its exact semantics — a filterKind forces
     * target:'audit', relatedUsers / relatedAccessRoles / relatedAdminRoles
     * each set only for their own kind; and the {#key} that remounts
     * LogViewer when the target, kind or id changes.
     *
     * ── Toggle, not Checkbox ─────────────────────────────────────────────
     * The discriminator is when the write happens. Flipping this switch takes
     * effect immediately — it rewrites localStorage and remounts the viewer
     * with new filters. There is no save bar, so it is a switch.
     *
     * ── LogViewer itself was migrated in place ───────────────────────────
     * 907 lines, of which the sveltestrap surface was one Alert and two
     * Tooltips. The virtualizer, the streaming and the pagination are
     * untouched — chrome only, the same scope the in-browser clients get.
     * Copying it would have duplicated 900 lines of logic to restyle 30.
     *
     * ── What the mockup shows that the API does not have ─────────────────
     * getLogs takes a search string and the related-entity filters, and
     * returns LogEntry rows. Omitted rather than faked:
     *   Date range / Actor / Severity / Target Cluster selects — no such
     *     parameters; there is no severity field on a log entry at all.
     *   "Export JSON / CSV" as separate formats — the existing download
     *     produces one format; the viewer's own download button is kept.
     *   Event Inspector panel with a signed JSON payload, "Merkle Root
     *     Verified", "HMAC-SHA256 Signature verified", "block #194,882",
     *     "STREAM SIGNED (ECDSA-P256)" and "zero-knowledge verification" —
     *     Warpgate does not sign its audit log, and claiming in the UI that
     *     it does would be a security misstatement, not a cosmetic one.
     *   Known Host Verification panel — belongs to /config/ssh (screen 17),
     *     not here, and its "Trust Anchor / VALIDATED" framing is invented.
     *   "Live stream active · 128 ev/min" — the viewer paginates, it does
     *     not stream, and there is no events-per-minute metric.
     */
    import { autosave } from 'common/autosave'
    import Toggle from 'ui/Toggle.svelte'
    import LogViewer from '../log-viewer/LogViewer.svelte'

    type FilterKind = 'user' | 'access-role' | 'admin-role'

    interface Props {
        params?: { id?: string }
        filterKind?: FilterKind
    }

    let { params, filterKind = undefined }: Props = $props()

    const [target] = autosave<'all' | 'audit'>('log.target', 'all')

    const filters = $derived({
        target: filterKind
            ? 'audit'
            : $target === 'audit'
              ? 'audit'
              : undefined,
        relatedUsers: filterKind === 'user' ? params?.id : undefined,
        relatedAccessRoles:
            filterKind === 'access-role' ? params?.id : undefined,
        relatedAdminRoles: filterKind === 'admin-role' ? params?.id : undefined,
    })

    const HEADINGS: Record<FilterKind, string> = {
        user: 'User audit log',
        'access-role': 'Access role audit log',
        'admin-role': 'Admin role audit log',
    }

    const heading = $derived(filterKind ? HEADINGS[filterKind] : 'Audit log')
</script>

<div class="log-page">
    <div class="head">
        <div>
            <h1>{heading}</h1>
            {#if filterKind}
                <p class="scope">
                    Scoped to
                    <code>{params?.id}</code>
                </p>
            {:else}
                <p class="scope">Everything Warpgate recorded, newest first.</p>
            {/if}
        </div>

        {#if !filterKind}
            <Toggle
                label="Audit log only"
                size="compact"
                checked={$target === 'audit'}
                onchange={() => {
                    $target = $target === 'audit' ? 'all' : 'audit'
                }}
                hint="Hides routine operational entries"
            />
        {/if}
    </div>

    <!-- Remount on any filter change: LogViewer holds paginated state. -->
    {#key `${$target}-${filterKind}-${params?.id}`}
        <LogViewer {filters} />
    {/key}
</div>

<style>
    .log-page {
        display: flex;
        flex-direction: column;
        height: 100%;
        min-height: 0;
    }

    .head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
        flex: none;
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .scope {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
