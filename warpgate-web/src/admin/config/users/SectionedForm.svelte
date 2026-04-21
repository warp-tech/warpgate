<script lang="ts">
    import { onMount, type Snippet } from 'svelte'

    interface Props {
        class?: string
        summary?: Snippet
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
    let summaryContentElement: HTMLElement | null = $state(null)
    let containerElement: HTMLElement | null = $state(null)
    let tabsElement: HTMLElement | null = $state(null)

    function updateActiveSectionFromScroll() {
        if (!containerElement || !tabsElement) {
            return
        }

        if (summaryContentElement && props.summary) {
            showSectionLinks = summaryContentElement.getBoundingClientRect().bottom <= 0
        } else {
            showSectionLinks = true
        }

        const tabsBottomInViewport = showSectionLinks
            ? tabsElement.getBoundingClientRect().bottom
            : 0
        let closestSection: Section | null = null
        let closestDistance = Infinity

        sections.forEach((section) => {
            if (!section.element) {
                return
            }

            const rect = section.element.getBoundingClientRect()
            // Distance from section top to the bottom of the sticky tabs
            const distanceFromTabs = rect.top - tabsBottomInViewport

            // Find the section closest to (just below) the sticky tabs
            if (rect.top < window.innerHeight && distanceFromTabs >= -100 && distanceFromTabs < closestDistance) {
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
        const sectionElements = containerElement?.querySelectorAll('[data-section]')
        if (sectionElements) {
            sections = Array.from(sectionElements).map((el) => ({
                id: (el as HTMLElement).dataset.section!,
                title: (el as HTMLElement).dataset.sectionTitle!,
                element: el as HTMLElement,
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
            headingElement.scrollIntoView({ behavior: 'smooth', block: 'start' })
        }
    }
</script>

<div class="sectioned-form-container {props.class ?? ''}">
    {#if sections.length > 0}
        <div class="sectioned-form-tabs-slot">
            <nav
                class="sectioned-form-tabs {showSectionLinks ? 'is-visible' : 'is-hidden'}"
                bind:this={tabsElement}
            >
                <div class="nav nav-pills gap-2 p-2 overflow-x-auto">
                    {#each sections as section (section.id)}
                        <a
                            href={`#${section.id}-heading`}
                            class="nav-link {activeSection === section.id ? 'active' : ''}"
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

    {#if props.summary}
        <div class="sectioned-form-summary-slot">
            <div class="sectioned-form-summary" bind:this={summaryContentElement}>
                {@render props.summary()}
            </div>
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
        min-height: 3.5rem;
    }

    .sectioned-form-tabs {
        border-bottom: 1px solid var(--bs-border-color);
        background: var(--bs-body-bg);
        transition: opacity 120ms ease;
    }

    .sectioned-form-tabs.is-hidden {
        opacity: 0;
        pointer-events: none;
        visibility: hidden;
    }

    .sectioned-form-tabs.is-visible {
        opacity: 1;
        pointer-events: auto;
        visibility: visible;
    }

    .sectioned-form-content {
        flex: 1;
    }
</style>
