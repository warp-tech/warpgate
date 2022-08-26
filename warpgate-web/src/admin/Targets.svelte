<script lang="ts">
import { api } from 'admin/lib/api'
import { link } from 'svelte-spa-router'
import { Alert, Spinner } from 'sveltestrap'
</script>

{#await api.getTargets()}
    <Spinner />
{:then targets}
    <div class="page-summary-bar">
        <h1>Targets</h1>
        <a
            class="btn btn-outline-secondary ms-auto"
            href="/targets/create"
            use:link>
            Add a target
        </a>
    </div>
    <div class="list-group list-group-flush">
        {#each targets as target}
            <!-- svelte-ignore a11y-missing-attribute -->
            <a
                class="list-group-item list-group-item-action"
                href="/targets/{target.id}"
                use:link>
                <strong class="me-auto">
                    {target.name}
                </strong>
                <small class="text-muted ms-auto">
                    {#if target.options.kind === 'Http'}
                        HTTP
                    {/if}
                    {#if target.options.kind === 'MySql'}
                        MySQL
                    {/if}
                    {#if target.options.kind === 'Ssh'}
                        SSH
                    {/if}
                    {#if target.options.kind === 'WebAdmin'}
                        This web admin interface
                    {/if}
                </small>
            </a>
        {/each}
    </div>
{:catch error}
    <Alert color="danger">{error}</Alert>
{/await}

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
