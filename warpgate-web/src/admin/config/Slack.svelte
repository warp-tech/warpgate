<script lang="ts">
    import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import {
        api,
        type SlackSettings,
        type SlackSettingsUpdate,
        type SlackTestResult,
    } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import CopyButton from 'common/CopyButton.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'

    let settings: SlackSettings | undefined = $state()
    // Secrets are write-only: empty fields keep what is stored
    let botToken = $state('')
    let signingSecret = $state('')
    let error: string | undefined = $state()
    let saved = $state(false)
    let testResult: SlackTestResult | undefined = $state()

    const interactivityUrl = `${location.origin}/@warpgate/api/slack/interactions`

    const initPromise = load()

    async function load() {
        settings = await api.getSlackSettings()
        return settings
    }

    function update(current: SlackSettings): SlackSettingsUpdate {
        return {
            enabled: current.enabled,
            botToken: botToken || undefined,
            signingSecret: signingSecret || undefined,
            ssoProvider: current.ssoProvider || undefined,
            channel: current.channel || undefined,
        }
    }

    async function save() {
        if (!settings) {
            return
        }
        error = undefined
        saved = false
        try {
            await api.updateSlackSettings({
                slackSettingsUpdate: update(settings),
            })
            botToken = ''
            signingSecret = ''
            await load()
            saved = true
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function test() {
        if (!settings) {
            return
        }
        error = undefined
        testResult = undefined
        try {
            testResult = await api.testSlackSettings({
                slackSettingsUpdate: update(settings),
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>slack</h1>
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit the Slack integration."
    >
        <p class="text-muted">
            Send session approval requests and ticket requests to admins in
            Slack and let them approve or reject from there. Admins with the
            <em>Approve sessions</em> permission get session approvals, and
            admins with <em>Manage ticket requests</em> get ticket requests, as
            direct messages matched to their Slack account by the e-mail of
            their SSO credential (for example their Google login).
        </p>

        {#if error}
            <Alert
                color="danger"
                dismissible
                onclose={() => {
                    error = undefined
                }}
                >{error}</Alert
            >
        {/if}

        <Loadable promise={initPromise}>
            {#snippet children()}
                {#if settings}
                    {#if settings.activeSource === 'config_file'}
                        <Alert color="info">
                            Slack is currently configured in the config file.
                            Settings enabled here take precedence over it.
                        </Alert>
                    {/if}

                    <form
                        onsubmit={e => {
                            e.preventDefault()
                            save()
                        }}
                    >
                        <label
                            for="slackEnabled"
                            class="d-flex align-items-center mb-3"
                        >
                            <Input
                                id="slackEnabled"
                                class="mb-0 me-2"
                                type="switch"
                                bind:checked={settings.enabled}
                            />
                            <div>Send approval requests to Slack</div>
                        </label>

                        <h4 class="mt-4">Slack app</h4>
                        <HelpText class="mb-3">
                            Create an app at api.slack.com/apps with the bot
                            scopes <code>chat:write</code>,
                            <code>users:read</code>
                            and
                            <code>users:read.email</code>, install it to your
                            workspace, and enable <em>Interactivity</em> with
                            this request URL:
                        </HelpText>
                        <div class="d-flex align-items-center mb-3">
                            <code class="me-2 text-break"
                                >{interactivityUrl}</code
                            >
                            <CopyButton text={interactivityUrl} />
                        </div>

                        <FormGroup floating label="Bot User OAuth Token">
                            <input
                                type="password"
                                class="form-control"
                                autocomplete="off"
                                placeholder={settings.botTokenSet
                                    ? '********'
                                    : 'xoxb-...'}
                                bind:value={botToken}
                            >
                        </FormGroup>
                        {#if settings.botTokenSet}
                            <HelpText class="mt-n2 mb-3">
                                A token is saved. Leave empty to keep it.
                            </HelpText>
                        {/if}

                        <FormGroup floating label="Signing secret">
                            <input
                                type="password"
                                class="form-control"
                                autocomplete="off"
                                placeholder="********"
                                bind:value={signingSecret}
                            >
                        </FormGroup>
                        {#if settings.signingSecretSet}
                            <HelpText class="mt-n2 mb-3">
                                A signing secret is saved. Leave empty to keep
                                it.
                            </HelpText>
                        {/if}

                        <h4 class="mt-4">Recipients</h4>
                        <FormGroup floating label="Match users by SSO provider">
                            <select
                                class="form-select"
                                bind:value={settings.ssoProvider}
                            >
                                <option value={undefined}>Any provider</option>
                                {#each settings.ssoProviders as provider (provider)}
                                    <option value={provider}>{provider}</option>
                                {/each}
                            </select>
                        </FormGroup>
                        <HelpText class="mt-n2 mb-3">
                            Only the e-mails of SSO credentials from this
                            provider are used to find admins in Slack. Admins
                            without one are found by their username if it is an
                            e-mail address.
                        </HelpText>

                        <FormGroup
                            floating
                            label="Also post to channel (optional)"
                        >
                            <input
                                type="text"
                                class="form-control"
                                autocomplete="off"
                                placeholder="C0123456789"
                                bind:value={settings.channel}
                            >
                        </FormGroup>
                        <HelpText class="mt-n2 mb-3">
                            A channel ID. Invite the app to the channel first.
                            Anyone there can click, but only Warpgate admins
                            with the permission are accepted.
                        </HelpText>

                        <div class="d-flex gap-2 mt-4">
                            <AsyncButton
                                type="button"
                                class="btn btn-primary"
                                click={save}
                            >
                                Save
                            </AsyncButton>
                            <AsyncButton
                                type="button"
                                color="secondary"
                                click={test}
                            >
                                Send me a test message
                            </AsyncButton>
                        </div>

                        {#if saved}
                            <Alert color="success" class="mt-3 mb-0">
                                Saved.
                            </Alert>
                        {/if}
                        {#if testResult}
                            <Alert
                                color={testResult.success
                                    ? 'success'
                                    : 'danger'}
                                class="mt-3 mb-0"
                            >
                                {testResult.success
                                    ? `Connected to ${testResult.workspace}. Check your Slack DMs.`
                                    : testResult.error}
                            </Alert>
                        {/if}
                    </form>
                {/if}
            {/snippet}
        </Loadable>
    </PermissionGate>
</div>
