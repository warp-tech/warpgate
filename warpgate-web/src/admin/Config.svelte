<script lang="ts">
import { api } from 'admin/lib/api'
import { link } from 'svelte-spa-router'
import { Alert, Spinner } from 'sveltestrap'
</script>

<div class="row">
    <div class="col-12 col-lg-6 mb-4 pe-4">
        <div class="page-summary-bar">
            <h1>Targets</h1>
            <a
                class="btn btn-outline-secondary ms-auto"
                href="/targets/create"
                use:link>
                Add a target
            </a>
        </div>

        {#await api.getTargets()}
            <Spinner />
        {:then targets}
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
    </div>

    <div class="col-12 col-lg-6 pe-4">
        <div class="page-summary-bar">
            <h1>Users</h1>
            <a
                class="btn btn-outline-secondary ms-auto"
                href="/users/create"
                use:link>
                Add a user
            </a>
        </div>

        {#await api.getUsers()}
            <Spinner />
        {:then users}
            <div class="list-group list-group-flush">
                {#each users as user}
                    <!-- svelte-ignore a11y-missing-attribute -->
                    <a
                        class="list-group-item list-group-item-action"
                        href="/users/{user.id}"
                        use:link>
                        <strong class="me-auto">
                            {user.username}
                        </strong>
                    </a>
                {/each}
            </div>
        {:catch error}
            <Alert color="danger">{error}</Alert>
        {/await}

        <div class="page-summary-bar mt-4">
            <h1>Roles</h1>
            <a
                class="btn btn-outline-secondary ms-auto"
                href="/roles/create"
                use:link>
                Add a role
            </a>
        </div>

        {#await api.getRoles()}
            <Spinner />
        {:then roles}
            <div class="list-group list-group-flush">
                {#each roles as role}
                    <!-- svelte-ignore a11y-missing-attribute -->
                    <a
                        class="list-group-item list-group-item-action"
                        href="/roles/{role.id}"
                        use:link>
                        <strong class="me-auto">
                            {role.name}
                        </strong>
                    </a>
                {/each}
            </div>
        {:catch error}
            <Alert color="danger">{error}</Alert>
        {/await}
    </div>
</div>

<style lang="scss">
    .list-group-item {
        display: flex;
        align-items: center;
    }
</style>
