<script lang="ts">
    import { faFileContract, faFlaskVial } from '@fortawesome/free-solid-svg-icons'
    import Fa from 'svelte-fa'
    import ApiTokenManager from './ApiTokenManager.svelte'
    import InfoBox from 'common/InfoBox.svelte'
</script>

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

<InfoBox class="mt-5">
    Pass the token in the <code>X-Warpgate-Token</code> header
</InfoBox>

<style lang="scss">
    .link {
        display: flex;
        align-items: center;

        span {
            margin-left: 0.25rem;
        }
    }
</style>
