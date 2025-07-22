<script lang="ts">
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import active from 'svelte-spa-router/active'
    import { classnames } from './sveltestrap-s5-ports/_sveltestrapUtils'

    interface Props {
        class?: string,
        title: string
        description?: string
        href: string
        small?: boolean
    }

    let {
        title,
        'class': className,
        description,
        href,
        small,
    }: Props = $props()

    let classes = $derived(classnames(
        className,
        'link',
        small ? 'sm' : false,
    ))
</script>

<a
    class={classes}
    href={href}
    use:link
    use:active
>
    <div class="text">
        <div class="title">{title}</div>
        {#if description}
            <div class="description text-muted">{description}</div>
        {/if}
    </div>
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

            .title {
                font-size: 1rem;
            }

            .description {
                font-size: 0.8rem;
            }

            .icon {
                display: none;
            }
        }
    }

</style>
