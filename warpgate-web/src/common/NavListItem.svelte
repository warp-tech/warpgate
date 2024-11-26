<script lang="ts">
    import { faArrowRight } from "@fortawesome/free-solid-svg-icons";
    import Fa from "svelte-fa";
import { link } from "svelte-spa-router";

    interface Props {
        title: string
        description?: string
        href: string
        // useLink?: boolean
        // icon?: string
        // children?: () => any
    }

    let {
        title,
        description,
        href,
        // useLink = false,
    }: Props = $props()
</script>

<a
    class="link"
    href={href}
    use:link
>
    <div class="text">
        <h5 class="title">{title}</h5>
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
        padding: 1rem 2rem;
        border-radius: var(--bs-border-radius);
        align-items: center;

        .text {
            flex-grow: 1;
        }

        &:hover {
            background: var(--bs-list-group-action-hover-bg);
            h5 {
                color: var(--bs-list-group-action-hover-color);
            }
        }

        &:active {
            background: var(--bs-list-group-action-active-bg);
            h5 {
                color: var(--bs-list-group-action-active-color);
            }
        }
    }

    h5 {
        margin-bottom: 0.25rem;

        text-decoration: underline;
        text-decoration-color: var(--wg-link-underline-color);
        text-underline-offset: 2px;
    }

    .link:hover h5 {
        text-decoration-color: var(--wg-link-hover-underline-color);
    }

    .description {
        text-decoration: none;
    }
</style>
