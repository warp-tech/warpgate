<script lang="ts">
import { api, UserSnapshot, TargetSnapshot, TicketSnapshot, TicketAndSecret } from 'lib/api'
import { link } from 'svelte-spa-router'
import { Alert } from 'sveltestrap'

let error: Error|null = null
let targets: TargetSnapshot[]|undefined
let users: UserSnapshot[]|undefined
let selectedTarget: TargetSnapshot|undefined
let selectedUser: UserSnapshot|undefined
let result: TicketAndSecret|undefined

async function load () {
    [targets, users] = await Promise.all([
        api.getTargets(),
        api.getUsers(),
    ])
}

load().catch(e => {
    error = e
})

async function create () {
    if (!selectedTarget || !selectedUser) {
        return
    }
    try {
        result = await api.createTicket({
            createTicketRequest: {
                username: selectedUser.username,
                targetName: selectedTarget.name,
            }
        })
    } catch (err) {
        error = err
    }
}

</script>

{#if error}
<Alert color="danger">{error.message}</Alert>
{/if}

{#if result}
    <input type="text" class="form-control" readonly value={result.secret} />
    <a
        class="btn btn-primary"
        href="/tickets"
        use:link
    >Done</a>
{:else}
    {#if users}
    <div class="form-group">
        <label>User</label>
        <select bind:value={selectedUser} class="form-control">
            {#each users as user}
                <option value={user}>
                    {user.username}
                </option>
            {/each}
        </select>
    </div>
    {/if}

    {#if targets}
    <div class="form-group">
        <label>Target</label>
        <select bind:value={selectedTarget} class="form-control">
            {#each targets as target}
                <option value={target}>
                    {target.name}
                </option>
            {/each}
        </select>
    </div>
    {/if}

    <button
        class="btn btn-primary"
        on:click={create}
    >Create</button>
{/if}
