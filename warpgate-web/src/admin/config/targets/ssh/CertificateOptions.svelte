<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import type {
        SecretBackendSummary,
        SSHTargetAuthSshTargetCertificateAuth,
    } from 'admin/lib/api'
    import { loadSecretBackends } from 'common/SecretRefInput.svelte'

    interface Props {
        auth: SSHTargetAuthSshTargetCertificateAuth
    }

    let { auth = $bindable() }: Props = $props()

    let backends = $state<SecretBackendSummary[]>([])
    loadSecretBackends().then(list => {
        backends = list
    })

    auth.backend ??= ''
    auth.mount ??= 'ssh'
</script>

<div class="row">
    <div class="col">
        <FormGroup floating label="Secret backend">
            <select class="form-control" bind:value={auth.backend} required>
                <option value="" disabled>Select a backend</option>
                {#each backends as backend (backend.id)}
                    <option value={backend.name}>{backend.name}</option>
                {/each}
            </select>
        </FormGroup>
    </div>
    <div class="col">
        <FormGroup floating label="SSH engine mount">
            <input class="form-control" bind:value={auth.mount} required>
        </FormGroup>
    </div>
    <div class="col">
        <FormGroup floating label="Signing role">
            <input class="form-control" bind:value={auth.role} required>
        </FormGroup>
    </div>
</div>
