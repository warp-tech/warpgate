<script lang="ts">
    import { Offcanvas } from '@sveltestrap/sveltestrap'
    import { link, router } from 'svelte-spa-router'
    import { sidebar } from './sidebarState.svelte'

    $effect(() => {
        void router.location // reference for effect
        sidebar.open = false
    })
</script>

{#snippet list()}
    {#each sidebar.items ?? [] as item (item.href)}
        {@const childActive = router.location.startsWith(`${item.href}/`)}
        {@const active = router.location === item.href}
        <div class="node" class:active>
            <a class="d-block" href={item.href} use:link>
                {item.title}
            </a>
        </div>

        {#if childActive && sidebar.current}
            <div class="node child active">
                <a class="d-block" href={router.location} use:link>
                    {sidebar.current}
                </a>
            </div>
        {/if}
    {/each}
{/snippet}

<nav class="sidebar d-none d-lg-block">
    {@render list()}
</nav>

<!-- Not Offcanvas's `lg` mode: sveltestrap inlines visibility:hidden while closed. -->
<Offcanvas
    class="d-lg-none"
    isOpen={sidebar.open}
    toggle={() => (sidebar.open = !sidebar.open)}
    placement="start"
>
    {@render list()}
</Offcanvas>

<style lang="scss">
    .sidebar {
        width: 270px;
        margin-right: 30px;
        flex: none;
    }

    .node {
        padding: var(--bs-list-group-item-padding-y) var(--bs-list-group-item-padding-x);

        &.active {
            background: var(--bs-list-group-action-hover-bg);
            border-radius: var(--bs-border-radius);
        }
    }

    .child {
        position: relative;
        padding-left: 3rem;

        &::before {
            content: '';
            position: absolute;
            left: 1.5rem;
            top: 50%;
            margin-top: -0.5rem;
            width: 0.75rem;
            height: 0.6rem;
            border-left: 1px solid var(--bs-secondary-color);
            border-bottom: 1px solid var(--bs-secondary-color);
        }
    }
</style>
