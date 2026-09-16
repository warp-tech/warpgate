<script lang="ts">
    import { onMount, type Snippet } from 'svelte'

    interface Props {
        class?: string
        children?: Snippet
    }

    const props: Props = $props()

    interface Section {
        id: string
        title: string
        element: HTMLElement | null
    }

    let sections: Section[] = $state([])
    let activeSection = $state<string | null>(null)
    let showSectionLinks = $state(false)
    let containerElement: HTMLElement | null = $state(null)
    let tabsElement: HTMLElement | null = $state(null)

    function updateActiveSectionFromScroll() {
        if (!containerElement || !tabsElement) {
            return
        }

        showSectionLinks = tabsElement.getBoundingClientRect().top <= 0

        const tabsBottomInViewport = showSectionLinks
            ? tabsElement.getBoundingClientRect().bottom
            : 0
        let closestSection: Section | null = null
        let closestDistance = Infinity

        sections.forEach(section => {
            if (!section.element) {
                return
            }

            const rect = section.element.getBoundingClientRect()
            // Distance from section top to the bottom of the sticky tabs
            const distanceFromTabs = rect.top - tabsBottomInViewport

            // Find the section closest to (just below) the sticky tabs
            if (
                rect.top < window.innerHeight &&
                distanceFromTabs >= -100 &&
                distanceFromTabs < closestDistance
            ) {
                closestDistance = distanceFromTabs
                closestSection = section
            }
        })

        // If nothing found, use the last section that has scrolled past the tabs
        if (!closestSection) {
            for (let i = sections.length - 1; i >= 0; i--) {
                const section = sections[i]
                if (!section) {
                    continue
                }
                if (section.element) {
                    const rect = section.element.getBoundingClientRect()
                    if (rect.top < tabsBottomInViewport) {
                        closestSection = section
                        break
                    }
                }
            }
        }

        if (closestSection && closestSection.id !== activeSection) {
            activeSection = closestSection.id
        }
    }

    onMount(() => {
        // Find all section elements
        const sectionElements = containerElement?.querySelectorAll(
            '[data-section]',
        ) as NodeListOf<HTMLElement>
        if (sectionElements) {
            sections = Array.from(sectionElements).map(el => ({
                // biome-ignore lint/style/noNonNullAssertion: x
                id: el.dataset.section!,
                // biome-ignore lint/style/noNonNullAssertion: x
                title: el.dataset.sectionTitle!,
                element: el,
            }))
            const firstSection = sections[0]
            if (firstSection) {
                activeSection = firstSection.id
            }
        }

        // Scroll event listener for responsive section tracking
        const handleScroll = () => {
            updateActiveSectionFromScroll()
        }

        window.addEventListener('scroll', handleScroll, { passive: true })
        window.addEventListener('resize', handleScroll)

        // Initial update
        updateActiveSectionFromScroll()

        return () => {
            window.removeEventListener('scroll', handleScroll)
            window.removeEventListener('resize', handleScroll)
        }
    })

    function scrollToSection(sectionId: string) {
        const headingElement = document.getElementById(`${sectionId}-heading`)
        if (headingElement) {
            activeSection = sectionId
            headingElement.scrollIntoView({
                behavior: 'smooth',
                block: 'start',
            })
        }
    }
</script>

<div class="sectioned-form-container {props.class ?? ''}">
    {#if sections.length > 0}
        <div
            class="sectioned-form-tabs-slot {showSectionLinks ? 'is-visible' : 'is-hidden'}"
        >
            <nav class="sectioned-form-tabs" bind:this={tabsElement}>
                <div class="section-tabs">
                    {#each sections as section (section.id)}
                        <a
                            href={`#${section.id}-heading`}
                            class="section-tab {activeSection === section.id ? 'active' : ''}"
                            onclick={(event) => {
                                event.preventDefault()
                                scrollToSection(section.id)
                            }}
                        >
                            {section.title}
                        </a>
                    {/each}
                </div>
            </nav>
        </div>
    {/if}

    <!-- Content -->
    <div class="sectioned-form-content" bind:this={containerElement}>
        {@render props.children?.()}
    </div>
</div>

<style>
    .sectioned-form-container {
        display: flex;
        flex-direction: column;
    }

    .sectioned-form-tabs-slot {
        position: sticky;
        top: 0;
        z-index: 10;
        height: 60px;
        margin-bottom: -60px;
        transition: opacity var(--wg-duration-fast) var(--wg-easing);
    }

    .sectioned-form-tabs-slot.is-hidden {
        opacity: 0;
        pointer-events: none;
    }

    .sectioned-form-tabs-slot.is-visible {
        opacity: 1;
        pointer-events: auto;
    }

    .sectioned-form-tabs {
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        background: var(--wg-surface);
        transition: opacity var(--wg-duration-fast) var(--wg-easing);

        flex-wrap: nowrap;
        white-space: nowrap;
    }

    .section-tabs {
        display: flex;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-sm);
        overflow-x: auto;
    }

    .section-tab {
        flex: none;
        display: inline-flex;
        align-items: center;
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-control-padding-x-compact);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        text-decoration: none;
        font: var(--wg-text-label-md);
        white-space: nowrap;
    }

    .section-tab:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .section-tab.active {
        background: var(--wg-surface-container-highest);
        color: var(--wg-text);
        box-shadow: inset 2px 0 0 var(--wg-primary);
    }

    .section-tab:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .sectioned-form-content {
        flex: 1;
    }
</style>
