<script lang="ts">
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import type { Snippet } from 'svelte'
    import Fa from 'svelte-fa'
    import { link, router } from 'svelte-spa-router'
    import { classnames } from './helpers'

    interface Props {
        class?: string
        title?: string
        titleSnippet?: Snippet<[]>
        description?: string
        descriptionSnippet?: Snippet<[]>
        addonSnippet?: Snippet<[]>
        href: string
        small?: boolean
    }

    let {
        title,
        titleSnippet,
        class: className,
        description,
        descriptionSnippet,
        addonSnippet,
        href,
        small,
    }: Props = $props()

    let active = $derived(router.loc.location === href)
    let classes = $derived(
        classnames(
            className,
            'link',
            small ? 'sm' : false,
            active ? 'active' : false,
        ),
    )
</script>

<a class={classes} {href} title={small ? description : undefined} use:link>
    <div class="text">
        <div class="title">
            {#if titleSnippet}
                {@render titleSnippet()}
            {:else}
                {title}
            {/if}
        </div>
        <div class="description text-muted">
            {#if descriptionSnippet}
                {@render descriptionSnippet()}
            {:else if description}
                {description}
            {/if}
        </div>
    </div>
    {@render addonSnippet?.()}
    <div class="icon">
        <Fa class="icon" icon={faArrowRight} />
    </div>
</a>

<style lang="scss">
    a {
        cursor: pointer;
        display: flex;
        width: 100%;
        text-decoration: none;
        padding: 0.8rem 1.5rem 1rem;
        border-radius: var(--bs-border-radius);
        align-items: center;
        gap: 1rem;

        .text {
            flex-grow: 1;
        }

        &:hover, &.active {
            background: var(--bs-list-group-action-hover-bg);
            .title {
                color: var(--bs-list-group-action-hover-color);
            }
        }

        &:active {
            background: var(--bs-list-group-action-active-bg);
            .title {
                color: var(--bs-list-group-action-active-color);
            }
        }

        .title {
            margin-bottom: 0.25rem;
            font-size: 1.25rem;

            text-decoration: underline;
            text-decoration-color: var(--wg-link-underline-color);
            text-underline-offset: 2px;
        }

        &.link:hover .title {
            text-decoration-color: var(--wg-link-hover-underline-color);
        }

        .description {
            text-decoration: none;
            line-height: 1rem;
            font-size: 0.9rem;
        }

        &.sm {
            padding: 0.5rem 1rem;

            // In the sidebar the titles are enough; the full config page
            // and the tooltip keep the descriptions
            .title {
                font-size: 1rem;
                margin-bottom: 0;
            }

            &.active .title {
                font-weight: 500;
            }

            .description {
                display: none;
            }

            .icon {
                display: none;
            }
        }
    }

</style>
