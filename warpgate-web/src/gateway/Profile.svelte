<script lang="ts">
    import { link } from 'svelte-spa-router'
    import { serverInfo } from './lib/store'
</script>

<div class="page-summary-bar">
    <h1>{$serverInfo?.username ?? 'Profile'}</h1>
</div>

<p><a use:link href="/profile/tokens">Manage API tokens</a></p>
<p><a href="/@warpgate/api/swagger">Admin API playground</a></p>
<p><a href="/@warpgate/admin/api/swagger">User API playground</a></p>
