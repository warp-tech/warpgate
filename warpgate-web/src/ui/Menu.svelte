<script lang="ts" module>
    export interface MenuItem {
        id: string
        label: string
        /** Renders as a link. Use a hash href; the router is hash-based. */
        href?: string
        disabled?: boolean
        /** Destructive items render in the error colour. */
        danger?: boolean
        /**
         * Present (true or false) makes this a checkable item:
         * role="menuitemcheckbox" with aria-checked, which is the correct
         * ARIA form for a preference that lives inside a menu. The portal's
         * "open targets in a new tab" switch was previously a raw switch
         * nested in a dropdown item, which announces as neither.
         */
        checked?: boolean
        /** Shown under the label — e.g. why an item is disabled. */
        hint?: string
        onselect?: () => void
    }

    export interface MenuGroup {
        /** Optional heading above the group. */
        label?: string
        items: MenuItem[]
    }
</script>

<script lang="ts">
    /**
     * NET-NEW primitive. Replaces sveltestrap's Dropdown, which screen 13
     * needs in two places — the list-level overflow menu and the per-row
     * actions menu — and which nothing else in ui/ covers.
     *
     * This is the APG *menu button* pattern, not a listbox and not a set of
     * buttons in a popover. It is implemented by hand because there is no
     * native element for it:
     *
     *   - the trigger carries aria-haspopup="menu" and aria-expanded
     *   - the surface is role="menu", its children role="menuitem"
     *   - Down/Up move between items and wrap; Home/End jump
     *   - typing a letter jumps to the next item starting with it
     *   - Escape closes and returns focus to the trigger, which is the part
     *     hand-rolled menus usually miss and which strands keyboard users
     *   - a click outside closes without swallowing that click's target
     *   - Enter/Space/Down on the trigger open and focus the first item
     *
     * Items are data rather than a snippet on purpose. A menu whose contents
     * are arbitrary markup cannot implement roving focus or type-ahead over
     * them, and both call sites here are lists of labelled actions.
     *
     * The menu is NOT focus-trapped. A menu is transient and Escape or an
     * outside click dismisses it; trapping focus in one is the wrong model
     * and makes Tab feel broken.
     */
    interface Props {
        groups: MenuGroup[]
        /** Accessible name for the trigger — required, it is icon-only. */
        label: string
        /** Visible trigger text. Omit for the icon-only overflow affordance. */
        triggerLabel?: string
        align?: 'start' | 'end'
        disabled?: boolean
        class?: string
    }

    let {
        groups,
        label,
        triggerLabel,
        align = 'end',
        disabled = false,
        class: className = '',
    }: Props = $props()

    let open = $state(false)
    let trigger: HTMLButtonElement | undefined = $state()
    let surface: HTMLDivElement | undefined = $state()
    let activeIndex = $state(0)
    let typeahead = ''
    let typeaheadTimer: ReturnType<typeof setTimeout> | undefined

    // Flattened, because focus moves across group boundaries.
    const flat = $derived(groups.flatMap(g => g.items).filter(i => !i.disabled))

    function itemElements(): HTMLElement[] {
        return surface
            ? Array.from(
                  surface.querySelectorAll<HTMLElement>(
                      '[role="menuitem"]:not([aria-disabled="true"]), [role="menuitemcheckbox"]:not([aria-disabled="true"])',
                  ),
              )
            : []
    }

    function focusAt(index: number) {
        const els = itemElements()
        if (!els.length) {
            return
        }
        const wrapped = (index + els.length) % els.length
        activeIndex = wrapped
        els[wrapped]?.focus()
    }

    function openMenu(focusLast = false) {
        if (disabled) {
            return
        }
        open = true
        // The surface has to exist before anything in it can take focus.
        queueMicrotask(() => focusAt(focusLast ? itemElements().length - 1 : 0))
    }

    function closeMenu({ restoreFocus = true } = {}) {
        if (!open) {
            return
        }
        open = false
        if (restoreFocus) {
            trigger?.focus()
        }
    }

    function select(item: MenuItem) {
        if (item.disabled) {
            return
        }
        if (item.checked !== undefined) {
            // A checkable item stays open so the tick can be seen to change,
            // which is the conventional behaviour and the only way to confirm
            // a preference took effect without reopening the menu.
            item.onselect?.()
            return
        }
        // Close first: the handler may navigate, and an open menu left behind
        // a route change is a stuck overlay.
        closeMenu()
        item.onselect?.()
    }

    function onTriggerKeydown(event: KeyboardEvent) {
        if (
            event.key === 'ArrowDown' ||
            event.key === 'Enter' ||
            event.key === ' '
        ) {
            event.preventDefault()
            openMenu()
        } else if (event.key === 'ArrowUp') {
            event.preventDefault()
            openMenu(true)
        }
    }

    function onSurfaceKeydown(event: KeyboardEvent) {
        switch (event.key) {
            case 'Escape':
                event.preventDefault()
                event.stopPropagation()
                closeMenu()
                return
            case 'ArrowDown':
                event.preventDefault()
                focusAt(activeIndex + 1)
                return
            case 'ArrowUp':
                event.preventDefault()
                focusAt(activeIndex - 1)
                return
            case 'Home':
                event.preventDefault()
                focusAt(0)
                return
            case 'End':
                event.preventDefault()
                focusAt(itemElements().length - 1)
                return
            case 'Tab':
                // Tabbing away dismisses, without yanking focus back.
                closeMenu({ restoreFocus: false })
                return
        }

        if (event.key.length === 1 && !event.metaKey && !event.ctrlKey) {
            typeahead += event.key.toLowerCase()
            clearTimeout(typeaheadTimer)
            typeaheadTimer = setTimeout(() => {
                typeahead = ''
            }, 600)
            const match = flat.findIndex(i =>
                i.label.toLowerCase().startsWith(typeahead),
            )
            if (match >= 0) {
                focusAt(match)
            }
        }
    }

    // Pointerdown rather than click: closing on click would fire after the
    // outside element already handled its own click, which is fine, but
    // pointerdown makes the menu feel dismissed the moment you press.
    function onWindowPointerDown(event: PointerEvent) {
        if (!open) {
            return
        }
        const t = event.target as Node
        if (trigger?.contains(t) || surface?.contains(t)) {
            return
        }
        closeMenu({ restoreFocus: false })
    }
</script>

<svelte:window onpointerdown={onWindowPointerDown} />

<div class="wg-menu {className}">
    <button
        bind:this={trigger}
        type="button"
        class="wg-menu-trigger"
        class:wg-menu-trigger-icon={!triggerLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={triggerLabel ? undefined : label}
        {disabled}
        onclick={() => (open ? closeMenu() : openMenu())}
        onkeydown={onTriggerKeydown}
    >
        {#if triggerLabel}
            <span>{triggerLabel}</span>
        {/if}
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <circle cx="8" cy="3" r="1.4" fill="currentColor" />
            <circle cx="8" cy="8" r="1.4" fill="currentColor" />
            <circle cx="8" cy="13" r="1.4" fill="currentColor" />
        </svg>
    </button>

    {#if open}
        <div
            bind:this={surface}
            class="wg-menu-surface wg-menu-{align}"
            role="menu"
            aria-label={label}
            tabindex="-1"
            onkeydown={onSurfaceKeydown}
        >
            {#each groups as group, gi (group.label ?? gi)}
                {#if group.label}
                    <p class="wg-menu-heading" role="presentation">
                        {group.label}
                    </p>
                {/if}
                {#each group.items as item (item.id)}
                    {#if item.href}
                        <a
                            role="menuitem"
                            class="wg-menu-item"
                            class:wg-menu-item-danger={item.danger}
                            href={item.href}
                            tabindex="-1"
                            aria-disabled={item.disabled ? 'true' : undefined}
                            onclick={() => closeMenu({ restoreFocus: false })}
                        >
                            {item.label}
                        </a>
                    {:else if item.checked === undefined}
                        <button
                            role="menuitem"
                            type="button"
                            class="wg-menu-item"
                            class:wg-menu-item-danger={item.danger}
                            tabindex="-1"
                            disabled={item.disabled}
                            aria-disabled={item.disabled ? 'true' : undefined}
                            onclick={() => select(item)}
                        >
                            <span class="wg-menu-item-text">
                                {item.label}
                                {#if item.hint}
                                    <span class="wg-menu-hint"
                                        >{item.hint}</span
                                    >
                                {/if}
                            </span>
                        </button>
                    {:else}
                        <button
                            role="menuitemcheckbox"
                            aria-checked={item.checked}
                            type="button"
                            class="wg-menu-item wg-menu-item-check"
                            class:wg-menu-item-danger={item.danger}
                            tabindex="-1"
                            disabled={item.disabled}
                            aria-disabled={item.disabled ? 'true' : undefined}
                            onclick={() => select(item)}
                        >
                            <span class="wg-menu-tick" aria-hidden="true">
                                {#if item.checked}
                                    <svg
                                        viewBox="0 0 16 16"
                                        width="12"
                                        height="12"
                                        aria-hidden="true"
                                    >
                                        <path
                                            d="M3.5 8.5l3 3L12.5 5"
                                            fill="none"
                                            stroke="currentColor"
                                            stroke-width="2"
                                            stroke-linecap="round"
                                            stroke-linejoin="round"
                                        />
                                    </svg>
                                {/if}
                            </span>
                            <span class="wg-menu-item-text">
                                {item.label}
                                {#if item.hint}
                                    <span class="wg-menu-hint"
                                        >{item.hint}</span
                                    >
                                {/if}
                            </span>
                        </button>
                    {/if}
                {/each}
            {/each}
        </div>
    {/if}
</div>

<style>
    .wg-menu {
        position: relative;
        display: inline-flex;
    }

    .wg-menu-trigger {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        background: none;
        border: var(--wg-border-width) solid transparent;
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        cursor: pointer;
    }

    .wg-menu-trigger-icon {
        width: var(--wg-control-height-compact);
        justify-content: center;
        padding: 0;
    }

    .wg-menu-trigger:hover:not(:disabled) {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-menu-trigger:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .wg-menu-trigger:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .wg-menu-surface {
        position: absolute;
        top: calc(100% + var(--wg-space-xs));
        z-index: 40;
        min-width: 12rem;
        padding: var(--wg-space-xs);
        background: var(--wg-surface-container-high);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-panel);
        box-shadow: var(--wg-shadow-overlay);
    }

    .wg-menu-end {
        right: 0;
    }

    .wg-menu-start {
        left: 0;
    }

    .wg-menu-heading {
        margin: var(--wg-space-xs) var(--wg-space-sm);
        font: var(--wg-text-label-sm);
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: var(--wg-text-subtle);
    }

    .wg-menu-item {
        display: block;
        width: 100%;
        padding: var(--wg-space-xs) var(--wg-space-sm);
        background: none;
        border: 0;
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
        text-align: left;
        text-decoration: none;
        cursor: pointer;
    }

    .wg-menu-item:hover:not([aria-disabled="true"]),
    .wg-menu-item:focus-visible {
        background: var(--wg-surface-container-highest);
    }

    .wg-menu-item:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: calc(var(--wg-focus-ring-offset) * -1);
    }

    .wg-menu-item-check {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-xs);
    }

    .wg-menu-tick {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 14px;
        flex: none;
        margin-top: 2px;
        color: var(--wg-primary);
    }

    .wg-menu-item-text {
        display: flex;
        flex-direction: column;
        min-width: 0;
    }

    .wg-menu-hint {
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .wg-menu-item-danger {
        color: var(--wg-error);
    }

    .wg-menu-item[aria-disabled="true"] {
        opacity: 0.45;
        cursor: not-allowed;
    }
</style>
