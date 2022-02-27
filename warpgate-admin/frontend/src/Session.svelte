<script lang="ts">
import { api } from 'lib/api';

import { Alert, Spinner } from 'sveltestrap'

export let params = { id: '' }

let error: Error|null = null
let session: any = null

async function load () {
    session = await api.getSession(params)
}

load().catch(e => {
    error = e
})

</script>

{#if session}
<h1>{session.id}</h1>
{/if}

{#if !session && !error}
<Spinner />
{/if}

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}
