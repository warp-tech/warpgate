<script lang="ts">
    import { api, type ProfileData } from 'gateway/lib/api'

    import { serverInfo } from 'gateway/lib/store'
    import UserCredentialsEditor from 'admin/UserCredentialsEditor.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import Alert from 'common/Alert.svelte'
    import { stringifyError } from 'common/errors'
    import AsyncButton from 'common/AsyncButton.svelte'

    let error: string|null = $state(null)
    let profile: ProfileData | undefined = $state()

    async function load () {
        try {
            profile = await api.getProfile()
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function update () {
        try {
            profile = await api.updateProfile({
                profileDataRequest: profile!,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="page-summary-bar">
    <div>
        <h1>{$serverInfo!.username}</h1>
        <div class="text-muted">User</div>
    </div>
</div>


{#await load()}
<DelayedSpinner />
{:then}
{#if profile}
<UserCredentialsEditor bind:value={profile.credentials} username={$serverInfo!.username!} />
{/if}
{/await}

{#if error}
<Alert color="danger">{error}</Alert>
{/if}


<div class="d-flex">
    <AsyncButton
        class="ms-auto"
        outline
        click={update}
    >Save</AsyncButton>
</div>
