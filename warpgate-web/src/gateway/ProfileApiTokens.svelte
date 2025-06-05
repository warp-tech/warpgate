<script lang="ts">
    import { faFileContract, faFlaskVial, faInfoCircle } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import ApiTokenManager from './ApiTokenManager.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
</script>

<!-- <div class="page-summary-bar">
    <h1>API tokens</h1>
</div> -->

<ApiTokenManager />

<div class="row mt-5">
    <div class="col">
        <h4>User API</h4>
        <a class="link" target="_blank" href="/@warpgate/api/playground">
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
        <a class="link" target="_blank" href="/@warpgate/admin/api/playground">
            <Fa icon={faFlaskVial} fw />
            <span>Playground</span>
        </a>
        <a class="link" target="_blank" href="/@warpgate/admin/api/openapi.json">
            <Fa icon={faFileContract} fw />
            <span>Schema</span>
        </a>
    </div>
</div>

<div class="text-muted d-flex align-items-center mt-5">
    <Fa icon={faInfoCircle} class="me-2" />
    <small>
        Pass the token in the <code>X-Warpgate-Token</code> header
    </small>
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
