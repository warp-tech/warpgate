<script lang="ts">
    import { Alert, FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { api, type ParameterValues } from 'admin/lib/api'
    import HelpText from 'admin/lib/HelpText.svelte'
    import Section from 'admin/lib/Section.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import ParametersForm from './ParametersForm.svelte'

    let parameters: ParameterValues | undefined = $state()

    // Switching the storage kind / credential mode replaces the object with a
    // fresh variant, since the tagged enum can't hold both shapes at once.
    function setStorageKind(kind: string): void {
        if (!parameters) {
            return
        }
        parameters.recordingsStorage =
            kind === 'S3'
                ? {
                      kind: 'S3',
                      bucket: '',
                      region: 'us-east-1',
                      pathStyle: false,
                      prefix: '',
                      credentials: { mode: 'Auto' },
                  }
                : { kind: 'Disk', path: './data/recordings' }
    }

    function setCredentialMode(mode: string): void {
        if (parameters?.recordingsStorage.kind !== 'S3') {
            return
        }
        // Omit secretAccessKey so an untouched field keeps the stored secret.
        parameters.recordingsStorage.credentials =
            mode === 'Static'
                ? { mode: 'Static', accessKeyId: '' }
                : { mode: 'Auto' }
    }

    let testResult: { success: boolean; error?: string } | undefined = $state()

    // Sends the edited config as-is; an untouched secret round-trips as
    // undefined and the server refills it from the stored value.
    async function testStorage(): Promise<void> {
        if (parameters?.recordingsStorage.kind !== 'S3') {
            return
        }
        testResult = undefined
        testResult = await api.testRecordingsStorage({
            recordingsStorageConfig: parameters.recordingsStorage,
        })
        if (!testResult.success) {
            throw new Error(testResult.error ?? 'Connection failed')
        }
    }
</script>

<ParametersForm title="recordings" bind:parameters>
    {#snippet children(parameters)}
        <label for="recordingsEnable" class="d-flex align-items-center mb-4">
            <Input
                id="recordingsEnable"
                class="mb-0 me-2"
                type="switch"
                bind:checked={parameters.recordingsEnable}
            />
            <div>Record sessions</div>
        </label>
        {#if parameters.recordingsEnable}
            <Section id="storage" title="Storage">
                <FormGroup floating label="Storage backend">
                    <select
                        id="recordingsStorage"
                        class="form-select"
                        value={parameters.recordingsStorage.kind}
                        onchange={e => setStorageKind(e.currentTarget.value)}
                    >
                        <option value="Disk">Local disk</option>
                        <option value="S3">S3 / S3-compatible</option>
                    </select>
                </FormGroup>

                <HelpText>
                    Changing the storage location applies to new recordings
                    only, copy existing recordings to the new location manually.
                </HelpText>

                {#if parameters.recordingsStorage.kind === 'Disk'}
                    {@const disk = parameters.recordingsStorage}
                    <FormGroup floating label="Recordings path">
                        <input
                            type="text"
                            class="form-control"
                            bind:value={disk.path}
                        >
                    </FormGroup>
                {:else if parameters.recordingsStorage.kind === 'S3'}
                    {@const s3 = parameters.recordingsStorage}
                    <FormGroup floating label="Bucket">
                        <input
                            type="text"
                            class="form-control"
                            required
                            bind:value={s3.bucket}
                        >
                    </FormGroup>
                    <HelpText>
                        The bucket needs a CORS policy allowing this origin to
                        issue GET requests with a Range header.
                    </HelpText>
                    <FormGroup floating label="Region">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="us-east-1"
                            required
                            bind:value={s3.region}
                        >
                    </FormGroup>
                    <FormGroup floating label="Endpoint (blank = AWS)">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="https://minio.example.com:9000"
                            value={s3.endpoint ?? ''}
                            oninput={e =>
                                (s3.endpoint =
                                    e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <FormGroup floating label="Key prefix">
                        <input
                            type="text"
                            class="form-control"
                            bind:value={s3.prefix}
                        >
                    </FormGroup>
                    <FormGroup floating label="Local scratch directory">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="data/recordings-scratch"
                            value={s3.scratchPath ?? ''}
                            oninput={e =>
                                (s3.scratchPath =
                                    e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <HelpText>
                        Recordings are buffered here before upload. Relative
                        paths resolve against the config file's directory, which
                        the Warpgate user must be able to write to.
                    </HelpText>
                    <label
                        for="recordingsS3PathStyle"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="recordingsS3PathStyle"
                            class="mb-0 me-2"
                            type="switch"
                            bind:checked={s3.pathStyle}
                        />
                        <div>Path-style addressing</div>
                    </label>
                    <HelpText>
                        Most S3-compatible services (e.g. MinIO, RustFS) require
                        path-style addressing.
                    </HelpText>

                    <FormGroup floating label="Credentials">
                        <select
                            id="recordingsS3CredentialMode"
                            class="form-select"
                            value={s3.credentials.mode}
                            onchange={e =>
                                setCredentialMode(e.currentTarget.value)}
                        >
                            <option value="Auto">
                                Automatic (environment or role-based)
                            </option>
                            <option value="Static">Access key</option>
                        </select>
                    </FormGroup>

                    {#if s3.credentials.mode === 'Static'}
                        {@const creds = s3.credentials}
                        <FormGroup floating label="Access key ID">
                            <input
                                type="text"
                                class="form-control"
                                autocomplete="off"
                                bind:value={creds.accessKeyId}
                            >
                        </FormGroup>
                        <FormGroup floating label="Secret access key">
                            <input
                                type="password"
                                class="form-control"
                                autocomplete="off"
                                placeholder="********"
                                bind:value={creds.secretAccessKey}
                            >
                        </FormGroup>
                    {/if}

                    <AsyncButton
                        type="button"
                        color="secondary"
                        click={testStorage}
                    >
                        Test connection
                    </AsyncButton>
                    {#if testResult}
                        <Alert
                            color={testResult.success ? 'success' : 'danger'}
                            class="mt-2 mb-0"
                        >
                            {testResult.success
                                ? 'Connection successful'
                                : testResult.error}
                        </Alert>
                    {/if}
                {/if}
            </Section>

            <Section id="options" title="Options">
                <label
                    for="recordDesktopKeyboardInput"
                    class="d-flex align-items-center mb-2"
                >
                    <Input
                        id="recordDesktopKeyboardInput"
                        class="mb-0 me-2"
                        type="switch"
                        bind:checked={parameters.recordDesktopKeyboardInput}
                    />
                    <div>Record remote desktop keyboard input</div>
                </label>
                <HelpText>
                    Disable if recording passwords typed in by users in various
                    applications is a security concern.
                </HelpText>
                <label for="recordScp" class="d-flex align-items-center mt-2">
                    <Input
                        id="recordScp"
                        class="mb-0 me-2"
                        type="switch"
                        bind:checked={parameters.recordScp}
                    />
                    <div>Record legacy SCP transfers</div>
                </label>
                <HelpText>
                    Legacy SCP works over an exec channel and would be normally
                    recorded like any other command. Disable to prevent SCP
                    recordings from wasting storage space.
                </HelpText>
            </Section>
        {/if}
    {/snippet}
</ParametersForm>
