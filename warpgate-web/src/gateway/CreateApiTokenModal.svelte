<script lang="ts">
    /**
     * New API token — screen 14. Migrated in place.
     *
     * ── Enumeration of the original, asserted present ────────────────────
     * A default lifetime of 7 days, clamped by serverInfo's
     * maxApiTokenDurationSeconds when the server sets one; initialLabel and
     * initialExpiryMs from the deep-link query parameters, with the expiry
     * clamped to the maximum as well; a `max` on the expiry field; the
     * "Maximum: N days" hint when a limit exists; focus into the label field
     * on open; create(label, new Date(expiry)) then close and clear.
     *
     * ── Changed: the submit path ─────────────────────────────────────────
     * The original's Create button only set `validated = true` and relied on
     * being a default-type button inside sveltestrap's <Form> to also submit.
     * That is two mechanisms doing one job, and the visible one did not do it.
     * This is a real <form> with a type="submit" button, so Enter in either
     * field submits and `required` is enforced by the browser — which is what
     * `validated` was approximating.
     */

    import { serverInfo } from 'gateway/lib/store'
    import { untrack } from 'svelte'
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import 'ui/layout.css'

    interface Props {
        isOpen: boolean
        create: (label: string, expiry: Date) => void
        initialLabel?: string
        initialExpiryMs?: number
    }

    const WEEK_MS = 1000 * 60 * 60 * 24 * 7

    const maxDurationMs = $serverInfo?.maxApiTokenDurationSeconds
        ? $serverInfo.maxApiTokenDurationSeconds * 1000
        : null

    const defaultDurationMs = maxDurationMs
        ? Math.min(maxDurationMs, WEEK_MS)
        : WEEK_MS

    let {
        isOpen = $bindable(true),
        create,
        initialLabel = '',
        initialExpiryMs = defaultDurationMs,
    }: Props = $props()

    // Seeded once. ApiTokenManager mounts this behind {#if creatingToken},
    // so a fresh component exists per open and the initial read is correct.
    const validatedInitialExpiryMs = untrack(() =>
        maxDurationMs
            ? Math.min(initialExpiryMs, maxDurationMs)
            : initialExpiryMs,
    )

    // svelte-ignore state_referenced_locally
    let label = $state(initialLabel)
    // svelte-ignore state_referenced_locally
    let expiry = $state(
        new Date(Date.now() + validatedInitialExpiryMs)
            .toISOString()
            .slice(0, 16),
    )

    const maxExpiryDate = maxDurationMs
        ? new Date(Date.now() + maxDurationMs)
        : undefined
    const maxExpiry = maxExpiryDate?.toISOString().slice(0, 16)

    function save() {
        if (!label.trim()) {
            return
        }
        create(label, new Date(expiry))
        cancel()
    }

    function cancel() {
        isOpen = false
        label = ''
    }
</script>

<Modal bind:open={isOpen} title="New API token" size="sm" onclose={cancel}>
    <form
        id="wg-new-api-token"
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            save()
        }}
    >
        <Input
            label="Descriptive label"
            required
            autofocus
            bind:value={label}
            hint="What this token is for. It is the only way to tell tokens apart later."
        />

        <Input
            label="Expiry"
            type="datetime-local"
            max={maxExpiry}
            bind:value={expiry}
            hint={maxDurationMs !== null
                ? `Maximum ${Math.floor(maxDurationMs / 86400 / 1000)} days, set by your administrator.`
                : undefined}
        />
    </form>

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="wg-new-api-token"
            disabled={!label.trim()}
        >
            Create
        </Button>
    {/snippet}
</Modal>
