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
        if (kind === 'S3') {
            parameters.recordingsStorage = {
                kind: 'S3',
                bucket: '',
                region: 'us-east-1',
                pathStyle: false,
                prefix: '',
                credentials: { mode: 'Auto' },
                serveThroughWarpgate: false,
            }
        } else if (kind === 'Azure') {
            parameters.recordingsStorage = {
                kind: 'Azure',
                account: '',
                container: '',
                prefix: '',
                credentials: { mode: 'ManagedIdentity' },
                serveThroughWarpgate: true,
            }
        } else {
            parameters.recordingsStorage = {
                kind: 'Disk',
                path: './data/recordings',
            }
        }
    }

    function setCredentialMode(mode: string): void {
        const storage = parameters?.recordingsStorage
        if (storage?.kind === 'S3') {
            // Omit secretAccessKey so an untouched field keeps the stored secret.
            storage.credentials =
                mode === 'Static'
                    ? { mode: 'Static', accessKeyId: '' }
                    : { mode: 'Auto' }
        } else if (storage?.kind === 'Azure') {
            // Only a service principal carries anything to fill in; the other
            // modes resolve their credential from the environment.
            if (mode === 'ServicePrincipal') {
                storage.credentials = {
                    mode: 'ServicePrincipal',
                    tenantId: '',
                    clientId: '',
                    clientSecret: '',
                }
            } else if (mode === 'WorkloadIdentity') {
                storage.credentials = { mode: 'WorkloadIdentity' }
            } else if (mode === 'DeveloperTools') {
                storage.credentials = { mode: 'DeveloperTools' }
            } else {
                storage.credentials = { mode: 'ManagedIdentity' }
            }
        }
    }

    let testResult: { success: boolean; error?: string } | undefined = $state()

    // Sends the edited config as-is; an untouched secret round-trips as
    // undefined and the server refills it from the stored value.
    async function testStorage(): Promise<void> {
        const storage = parameters?.recordingsStorage
        if (!storage || storage.kind === 'Disk') {
            return
        }
        testResult = undefined
        testResult = await api.testRecordingsStorage({
            recordingsStorageConfig: storage,
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
                        <option value="Azure">Azure Blob Storage</option>
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
                {:else if parameters.recordingsStorage.kind === 'Azure'}
                    {@const azure = parameters.recordingsStorage}
                    <FormGroup floating label="Storage account">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="mywarpgatestorage"
                            required
                            bind:value={azure.account}
                        >
                    </FormGroup>
                    <FormGroup floating label="Container">
                        <input
                            type="text"
                            class="form-control"
                            required
                            bind:value={azure.container}
                        >
                    </FormGroup>
                    <FormGroup floating label="Endpoint (blank = public Azure)">
                        <input
                            type="text"
                            class="form-control"
                            placeholder="https://myaccount.blob.core.windows.net"
                            value={azure.endpoint ?? ''}
                            oninput={e =>
                                (azure.endpoint =
                                    e.currentTarget.value || undefined)}
                        >
                    </FormGroup>
                    <HelpText>Set this for sovereign clouds.</HelpText>
                    <FormGroup floating label="Blob prefix">
                        <input
                            type="text"
                            class="form-control"
                            bind:value={azure.prefix}
                        >
                    </FormGroup>

                    <FormGroup floating label="Credentials">
                        <select
                            id="recordingsAzureCredentialMode"
                            class="form-select"
                            value={azure.credentials.mode}
                            onchange={e =>
                                setCredentialMode(e.currentTarget.value)}
                        >
                            <option value="ManagedIdentity">
                                Managed identity
                            </option>
                            <option value="WorkloadIdentity">
                                Workload identity (AKS)
                            </option>
                            <option value="ServicePrincipal">
                                Service principal
                            </option>
                            <option value="DeveloperTools">
                                Azure CLI (development)
                            </option>
                        </select>
                    </FormGroup>
                    <HelpText>
                        A storage account key cannot be used: the Azure SDK
                        authenticates with Entra ID only.
                    </HelpText>

                    {#if azure.credentials.mode === 'ManagedIdentity'}
                        {@const creds = azure.credentials}
                        <FormGroup
                            floating
                            label="Client ID (blank = system-assigned)"
                        >
                            <input
                                type="text"
                                class="form-control"
                                autocomplete="off"
                                value={creds.clientId ?? ''}
                                oninput={e =>
                                    (creds.clientId =
                                        e.currentTarget.value || undefined)}
                            >
                        </FormGroup>
                        <HelpText>
                            Set this only for a user-assigned identity.
                        </HelpText>
                    {:else if azure.credentials.mode === 'WorkloadIdentity'}
                        <HelpText>
                            Taken from the pod environment: AZURE_TENANT_ID,
                            AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE.
                        </HelpText>
                    {:else if azure.credentials.mode === 'ServicePrincipal'}
                        {@const creds = azure.credentials}
                        <FormGroup floating label="Tenant ID">
                            <input
                                type="text"
                                class="form-control"
                                autocomplete="off"
                                required
                                bind:value={creds.tenantId}
                            >
                        </FormGroup>
                        <FormGroup floating label="Client ID">
                            <input
                                type="text"
                                class="form-control"
                                autocomplete="off"
                                required
                                bind:value={creds.clientId}
                            >
                        </FormGroup>
                        <FormGroup floating label="Client secret">
                            <input
                                type="password"
                                class="form-control"
                                autocomplete="off"
                                placeholder="********"
                                bind:value={creds.clientSecret}
                            >
                        </FormGroup>
                    {:else}
                        <HelpText>
                            Uses the Azure CLI sign-in of the user running
                            Warpgate. For development only.
                        </HelpText>
                    {/if}
                {/if}

                {#if parameters.recordingsStorage.kind !== 'Disk'}
                    {@const remote = parameters.recordingsStorage}
                    <label
                        for="recordingsServeThroughWarpgate"
                        class="d-flex align-items-center mb-2"
                    >
                        <Input
                            id="recordingsServeThroughWarpgate"
                            class="mb-0 me-2"
                            type="switch"
                            bind:checked={remote.serveThroughWarpgate}
                        />
                        <div>Serve recordings through Warpgate</div>
                    </label>
                    <HelpText>
                        {#if remote.serveThroughWarpgate}
                            Playback is streamed by Warpgate, so the browser
                            never needs to reach the storage directly. Works
                            behind a private endpoint.
                        {:else}
                            Playback redirects the browser to a signed URL,
                            which is cheaper but needs the storage to be
                            reachable from the browser and to carry a CORS
                            policy allowing this origin to issue GET requests
                            with a Range header.
                        {/if}
                    </HelpText>

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
