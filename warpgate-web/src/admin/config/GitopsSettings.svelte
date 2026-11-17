<script lang="ts">
    import { faBook } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Button, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type GitopsSource, type ParameterUpdate } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import DurationInput from 'common/DurationInput.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import SecretRefInput from 'common/SecretRefInput.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'

    let source: GitopsSource | undefined = $state()
    let intervalSeconds: number | undefined = $state()
    let syncOnStartup = $state(true)
    let prune = $state(false)
    let webhookSecretSet = $state(false)
    let gitPasswordSet = $state(false)
    // The URL the stored password belongs to: the server drops it for any other
    let storedUrl: string | undefined = $state()

    // undefined keeps the stored secret, null removes it
    let webhookSecret: string | null | undefined = $state()
    // Clear was clicked: an emptied input stays null rather than reverting to "keep"
    let webhookCleared = $state(false)

    let formEl: HTMLFormElement | undefined = $state()
    let formValid = $state(true)
    let error: string | undefined = $state()

    const webhookUrl = `${location.origin}/@warpgate/api/gitops/webhook`

    async function load() {
        const parameters = await api.getParameters({})
        source = parameters.gitopsSource
        intervalSeconds = parameters.gitopsSyncIntervalSeconds
        syncOnStartup = parameters.gitopsSyncOnStartup
        prune = parameters.gitopsPrune
        webhookSecretSet = parameters.gitopsWebhookSecretSet
        gitPasswordSet = parameters.gitopsGitPasswordSet
        storedUrl =
            parameters.gitopsSource?.kind === 'Git'
                ? parameters.gitopsSource.url
                : undefined
    }

    const initPromise = load()

    let gitPasswordKept = $derived(
        gitPasswordSet &&
            source?.kind === 'Git' &&
            !source.password &&
            source.url === storedUrl,
    )
    let gitPasswordDropped = $derived(
        gitPasswordSet &&
            source?.kind === 'Git' &&
            !source.password &&
            source.url !== storedUrl,
    )

    function setKind(kind: string): void {
        source =
            kind === 'Git'
                ? { kind: 'Git', url: '', reference: 'main' }
                : kind === 'Directory'
                  ? { kind: 'Directory', path: '' }
                  : undefined
    }

    function refreshValidity() {
        formValid = formEl?.checkValidity() ?? false
    }

    // Runs after the DOM update, so fields shown for a new source kind count
    $effect(() => {
        void source?.kind
        if (formEl) {
            refreshValidity()
        }
    })

    async function save() {
        error = undefined
        try {
            // A cleared field must go out as null: undefined keeps the stored value
            const parameterUpdate = {
                gitopsSource: source ?? null,
                gitopsSyncIntervalSeconds: intervalSeconds ?? null,
                gitopsSyncOnStartup: syncOnStartup,
                gitopsPrune: prune,
                gitopsWebhookSecret: webhookSecret,
            } as unknown as ParameterUpdate
            await api.updateParameters({ parameterUpdate })
            if (webhookSecret !== undefined) {
                webhookSecretSet = webhookSecret !== null
                webhookSecret = undefined
                webhookCleared = false
            }
            // Reloads the redacted source, so a saved password shows as stored
            await load()
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>gitops settings</h1>
        {#if $serverInfo?.gitopsSync}
            <a class="ms-auto" href="/status/gitops" use:link>
                Sync status &amp; history
            </a>
        {/if}
    </div>

    <PermissionGate
        perm="configEdit"
        message="You have no permission to edit GitOps settings."
    >
        {#if error}
            <Alert color="danger">{error}</Alert>
        {/if}
        <Loadable promise={initPromise}>
            <form
                bind:this={formEl}
                oninput={refreshValidity}
                onchange={refreshValidity}
                onsubmit={e => {
                    e.preventDefault()
                    save()
                }}
            >
                <FormGroup floating label="Configuration source">
                    <select
                        class="form-select"
                        value={source?.kind ?? ''}
                        onchange={e => setKind(e.currentTarget.value)}
                    >
                        <option value="">None (API submission only)</option>
                        <option value="Git">Git repository</option>
                        <option value="Directory">Local directory</option>
                    </select>
                </FormGroup>

                {#if source?.kind === 'Directory'}
                    {@const dir = source}
                    <FormGroup floating label="Path">
                        <input
                            type="text"
                            class="form-control"
                            required
                            maxlength="4096"
                            bind:value={dir.path}
                        >
                    </FormGroup>
                    <HelpText>Must be mounted on every node</HelpText>
                {:else if source?.kind === 'Git'}
                    {@const git = source}
                    <FormGroup floating label="URL">
                        <input
                            type="url"
                            class="form-control"
                            required
                            maxlength="2048"
                            pattern="(https|file)://[^@\/]*(/.*)?"
                            placeholder="https://git.example.com/infra.git"
                            bind:value={git.url}
                        >
                    </FormGroup>
                    <FormGroup floating label="Branch, tag or commit">
                        <input
                            type="text"
                            class="form-control"
                            required
                            maxlength="255"
                            bind:value={git.reference}
                        >
                    </FormGroup>
                    <FormGroup floating label="Path within the repository">
                        <input
                            type="text"
                            class="form-control"
                            maxlength="4096"
                            pattern="[^\/\\.][^\/\\]*(\/[^\/\\.][^\/\\]*)*"
                            placeholder="Repository root"
                            value={git.path ?? ''}
                            oninput={e =>
                                (git.path = e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <FormGroup floating label="Username">
                        <input
                            type="text"
                            class="form-control"
                            autocomplete="off"
                            placeholder="Anonymous"
                            maxlength="255"
                            value={git.username ?? ''}
                            oninput={e =>
                                (git.username =
                                    e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <SecretRefInput
                        bind:value={git.password}
                        inlineLabel="Password or token"
                    />
                    {#if gitPasswordKept}
                        <HelpText>
                            A password or token is stored; leave empty to keep
                            it
                        </HelpText>
                    {:else if gitPasswordDropped}
                        <HelpText>
                            The stored password or token belongs to {storedUrl}
                            and will be dropped; enter one for the new URL
                        </HelpText>
                    {/if}
                {/if}

                {#if !source?.kind}
                    <a
                        href="/@warpgate/admin/api/playground#/operations/sync_gitops"
                        target="_blank"
                        class="d-flex align-items-center gap-2"
                    >
                        <Fa icon={faBook} />
                        Config submission API
                    </a>
                {/if}
                <a
                    href="XXX"
                    target="_blank"
                    class="mb-4 d-flex align-items-center gap-2"
                >
                    <Fa icon={faBook} />
                    [TODO] Config file format
                </a>

                <h4>Options</h4>
                <label for="gitopsPrune" class="d-flex align-items-center mb-4">
                    <Input
                        id="gitopsPrune"
                        class="mb-0 me-2"
                        type="switch"
                        bind:checked={prune}
                    />
                    <div>
                        Delete objects that are no longer present in the config
                    </div>
                </label>

                {#if source}
                    <h4>Automatic sync</h4>
                    <label
                        for="gitopsSyncOnStartup"
                        class="d-flex align-items-center mb-3"
                    >
                        <Input
                            id="gitopsSyncOnStartup"
                            class="mb-0 me-2"
                            type="switch"
                            bind:checked={syncOnStartup}
                        />
                        <div>Sync once when Warpgate starts</div>
                    </label>
                    <DurationInput
                        label="Sync every"
                        seconds={intervalSeconds}
                        onChange={v => {
                            intervalSeconds = v
                        }}
                    />

                    <HelpText>
                        For added safety, if more than half of the managed
                        objects are deleted in the config, a manual sync will be
                        required
                    </HelpText>

                    <h4>Webhook</h4>
                    <CopyableTextArea label="Webhook URL" value={webhookUrl} />
                    <div class="d-flex align-items-center">
                        <FormGroup
                            floating
                            label="Webhook secret"
                            class="flex-grow-1"
                        >
                            <input
                                type="password"
                                class="form-control"
                                autocomplete="off"
                                minlength="16"
                                maxlength="255"
                                placeholder={webhookSecretSet && !webhookCleared
                                    ? '********'
                                    : ' '}
                                value={webhookSecret ?? ''}
                                oninput={e =>
                                    (webhookSecret =
                                        e.currentTarget.value ||
                                        (webhookCleared ? null : undefined))}
                            >
                        </FormGroup>
                        {#if webhookSecretSet && !webhookCleared}
                            <Button
                                color="link"
                                class="ms-2 mb-3"
                                onclick={() => {
                                    webhookSecret = null
                                    webhookCleared = true
                                }}
                            >
                                Clear
                            </Button>
                        {/if}
                    </div>
                    <HelpText>
                        Supports GitHub, Gitea, Forgejo, GitLab and Bitbucket.
                        For Azure DevOps, use Basic authentication with any
                        username and this secret as the password.
                    </HelpText>
                {/if}

                <StickyActionBar>
                    <AsyncButton
                        type="button"
                        color="primary"
                        disabled={!formValid}
                        click={save}
                    >
                        Save
                    </AsyncButton>
                </StickyActionBar>
            </form>
        </Loadable>
    </PermissionGate>
</div>
