<script lang="ts">
    /**
     * A disclosure whose open state persists — screen 13, chrome only.
     *
     * Behaviour preserved: the open state is stored under `persistKey` via
     * common/autosave, `defaultOpen` seeds it, and both are fixed at mount.
     *
     * Added: `aria-expanded` and `aria-controls`. The original was a bare
     * button with a rotating chevron, so a screen reader user was told
     * nothing about whether the section was open or what the button
     * controlled — the chevron carried the whole message visually and none
     * of it otherwise.
     */
    import { autosave } from 'common/autosave'
    import type { Snippet } from 'svelte'

    interface Props {
        label: string
        persistKey: string
        defaultOpen?: boolean
        children: Snippet
    }

    const { label, persistKey, defaultOpen = false, children }: Props = $props()

    // svelte-ignore state_referenced_locally -- both are fixed at mount
    const [open] = autosave(persistKey, defaultOpen)

    const panelId = `wg-disclosure-${Math.random().toString(36).slice(2, 9)}`
</script>

<button
    type="button"
    class="disclosure"
    aria-expanded={$open}
    aria-controls={panelId}
    onclick={e => {
        e.preventDefault()
        open.set(!$open)
    }}
>
    <span class="caret" class:openCaret={$open} aria-hidden="true">
        <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
            <path
                d="M6 3.5L10.5 8L6 12.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.75"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
    </span>
    <span>{label}</span>
</button>

<div id={panelId} hidden={!$open}>
    {@render children()}
</div>

<style>
    .disclosure {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: 0;
        background: none;
        border: 0;
        color: var(--wg-primary);
        font: var(--wg-text-label-md);
        text-align: left;
        cursor: pointer;
    }

    .disclosure:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .caret {
        display: inline-flex;
        transition: transform var(--wg-duration-fast) var(--wg-easing);
    }

    .openCaret {
        transform: rotate(90deg);
    }

    @media (prefers-reduced-motion: reduce) {
        .caret {
            transition: none;
        }
    }
</style>
