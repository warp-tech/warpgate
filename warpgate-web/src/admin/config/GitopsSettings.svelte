<script lang="ts">
    import { Alert, Button, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type GitopsSource, type ParameterUpdate } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DurationInput from 'common/DurationInput.svelte'
    import { stringifyError } from 'common/errors'
    import Loadable from 'common/Loadable.svelte'
    import SecretRefInput from 'common/SecretRefInput.svelte'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { link } from 'svelte-spa-router'

    let source: GitopsSource | undefined = $state()
    let intervalSeconds: number | undefined = $state()
    let prune = $state(false)
    let webhookSecretSet = $state(false)
    // undefined keeps the stored secret, null removes it
    let webhookSecret: string | null | undefined = $state()

    let formEl: HTMLFormElement | undefined = $state()
    let formValid = $state(true)
    let error: string | undefined = $state()

    const webhookUrl = `${location.origin}/@warpgate/api/gitops/webhook`

    const initPromise = api.getParameters({}).then(parameters => {
        source = parameters.gitopsSource
        intervalSeconds = parameters.gitopsSyncIntervalSeconds
        prune = parameters.gitopsPrune
        webhookSecretSet = parameters.gitopsWebhookSecretSet
    })

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
                gitopsPrune: prune,
                gitopsWebhookSecret: webhookSecret,
            } as unknown as ParameterUpdate
            await api.updateParameters({ parameterUpdate })
            if (webhookSecret !== undefined) {
                webhookSecretSet = webhookSecret !== null
                webhookSecret = undefined
            }
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>gitops settings</h1>
        <a class="ms-auto" href="/manage/gitops" use:link>Sync history</a>
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
                <FormGroup floating label="Source">
                    <select
                        class="form-select"
                        value={source?.kind ?? ''}
                        onchange={e => setKind(e.currentTarget.value)}
                    >
                        <option value="">Off</option>
                        <option value="Git">Git repository</option>
                        <option value="Directory">Directory</option>
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
                    <HelpText>Must hold the same files on every node.</HelpText>
                {:else if source?.kind === 'Git'}
                    {@const git = source}
                    <FormGroup floating label="URL">
                        <input
                            type="url"
                            class="form-control"
                            required
                            maxlength="2048"
                            pattern="(https|file)://[^@/]*(/.*)?"
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
                    <FormGroup
                        floating
                        label="Path in the repository (blank = root)"
                    >
                        <input
                            type="text"
                            class="form-control"
                            maxlength="4096"
                            pattern="[^\/\\.][^\/\\]*(\/[^\/\\.][^\/\\]*)*"
                            value={git.path ?? ''}
                            oninput={e =>
                                (git.path = e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <FormGroup floating label="Username (blank = anonymous)">
                        <input
                            type="text"
                            class="form-control"
                            autocomplete="off"
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
                    <HelpText
                        >Blank keeps the stored password while the URL stays the
                        same.</HelpText
                    >
                {/if}

                {#if source}
                    <DurationInput
                        label="Sync interval (blank = no periodic sync)"
                        seconds={intervalSeconds}
                        onChange={v => {
                            intervalSeconds = v
                        }}
                    />

                    <label
                        for="gitopsPrune"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="gitopsPrune"
                            class="mb-0 me-2"
                            type="switch"
                            bind:checked={prune}
                        />
                        <div>Delete resources removed from the source</div>
                    </label>
                    <HelpText>
                        A sync that would delete more than half of the managed
                        resources applies nothing until forced from the sync
                        history.
                    </HelpText>

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
                                placeholder={webhookSecretSet &&
                                webhookSecret !== null
                                    ? '********'
                                    : ' '}
                                value={webhookSecret ?? ''}
                                oninput={e =>
                                    (webhookSecret =
                                        e.currentTarget.value || undefined)}
                            >
                        </FormGroup>
                        {#if webhookSecretSet && webhookSecret !== null}
                            <Button
                                color="link"
                                class="ms-2 mb-3"
                                onclick={() => (webhookSecret = null)}
                            >
                                Clear
                            </Button>
                        {/if}
                    </div>
                    <HelpText>
                        Pushes go to <code>{webhookUrl}</code>, signed with
                        <code>X-Hub-Signature-256</code>
                        or sent as <code>X-Gitlab-Token</code>.
                    </HelpText>
                {/if}

                <StickyActionBar>
                    <AsyncButton
                        type="button"
                        class="btn btn-primary"
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
