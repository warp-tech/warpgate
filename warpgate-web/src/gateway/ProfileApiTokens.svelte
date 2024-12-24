<script lang="ts">
    import { faFileContract, faFlaskVial } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import ApiTokenManager from './ApiTokenManager.svelte'
</script>

<!-- <div class="page-summary-bar">
    <h1>API tokens</h1>
</div> -->

<ApiTokenManager />

<div class="row">
    <div class="col">
        <h4>User API</h4>
        <a class="link" target="_blank" href="/@warpgate/api/swagger">
            <Fa icon={faFlaskVial} fw />
            <span>Playground</span>
        </a>
        <a class="link" target="_blank" href="/@warpgate/api/openapi.json">
            <Fa icon={faFileContract} fw />
            <span>Schema</span>
        </a>
    </div>

    <div class="col">
        <h4>Admin API</h4>
        <a class="link" target="_blank" href="/@warpgate/admin/api/swagger">
            <Fa icon={faFlaskVial} fw />
            <span>Playground</span>
        </a>
        <a class="link" target="_blank" href="/@warpgate/admin/api/openapi.json">
            <Fa icon={faFileContract} fw />
            <span>Schema</span>
        </a>
    </div>
</div>

<style lang="scss">
    .link {
        display: flex;
        align-items: center;

        span {
            margin-left: 0.25rem;
        }
    }
</style>
