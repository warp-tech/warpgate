<script lang="ts">
import { api, UserSnapshot } from 'admin/lib/api'
import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
import { TargetKind } from 'gateway/lib/api'
import { Alert, FormGroup, Spinner } from 'sveltestrap'

export let params: { id: string }

let selectedUser: UserSnapshot|undefined
</script>

{#await api.getTarget({ id: params.id })}
    <Spinner />
{:then target}
    <div class="page-summary-bar">
        <div>
            <h1>{target.name}</h1>
            <div class="text-muted">
                {#if target.options.kind === 'MySql'}
                    MySQL target
                {/if}
                {#if target.options.kind === 'Ssh'}
                    SSH target
                {/if}
                {#if target.options.kind === 'WebAdmin'}
                    This web admin interface
                {/if}
            </div>
        </div>
        <!-- <a
            class="btn btn-outline-secondary ms-auto"
            href="/targets/create"
            use:link>
            Add a target
        </a> -->
    </div>

    <h3>Access instructions</h3>

    {#if target.options.kind === 'Ssh' || target.options.kind === 'MySql'}
        {#await api.getUsers()}
            <Spinner/>
        {:then users}
            <FormGroup floating label="Select a user">
                <select bind:value={selectedUser} class="form-control">
                    {#each users as user}
                        <option value={user}>
                            {user.username}
                        </option>
                    {/each}
                </select>
            </FormGroup>
        {:catch error}
            <Alert color="danger">{error}</Alert>
        {/await}
    {/if}

    <ConnectionInstructions
        targetName={target.name}
        username={selectedUser?.username}
        targetKind={{
            Ssh: TargetKind.Ssh,
            WebAdmin: TargetKind.WebAdmin,
            Http: TargetKind.Http,
            MySql: TargetKind.MySql,
        }[target.options.kind ?? '']}
        targetExternalHost={target.options['externalHost']}
    />
{:catch error}
    <Alert color="danger">{error}</Alert>
{/await}
