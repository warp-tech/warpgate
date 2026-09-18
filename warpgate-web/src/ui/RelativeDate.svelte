<script lang="ts">
    /**
     * A date rendered as "3 days ago", with the absolute value available.
     *
     * Replaces common/RelativeDate.svelte, which wrapped the text in
     * sveltestrap's Tooltip. Two already-migrated screens imported it
     * (Sessions, Session), so it would have kept sveltestrap alive past the
     * deletion commit — the same trap as common/CopyButton.svelte.
     *
     * Deliberate divergence: the styled tooltip is gone, replaced by a native
     * `title`. ui/Tooltip reveals on hover and on focus, but it observes
     * focusin from its children, and a <time> element is not focusable — so
     * the styled tooltip could never reach a keyboard user here. Making the
     * date focusable to fix that would put a tab stop on every date cell in
     * every table, which is worse. `title` is announced as the accessible
     * description, works without JavaScript, and costs nothing.
     *
     * `datetime` carries the unambiguous machine value, which neither the
     * relative text nor a locale string does.
     */
    import { formatDistanceToNow } from 'date-fns'

    interface Props {
        date: Date
        /** Renders the absolute date instead, keeping the relative one in the title. */
        absolute?: boolean
        class?: string
    }

    let { date, absolute = false, class: className = '' }: Props = $props()

    const relative = $derived(formatDistanceToNow(date, { addSuffix: true }))
    const exact = $derived(date.toLocaleString())
    const iso = $derived(date.toISOString())
</script>

<time datetime={iso} title={absolute ? relative : exact} class={className}>
    {absolute ? exact : relative}
</time>

<style>
    time {
        white-space: nowrap;
    }
</style>
