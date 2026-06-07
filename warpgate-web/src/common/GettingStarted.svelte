<script lang="ts">
    import { faCircle } from '@fortawesome/free-regular-svg-icons'
    import { faCircleCheck, faExternalLink } from '@fortawesome/free-solid-svg-icons'
    import { ListGroup } from '@sveltestrap/sveltestrap'
    import { api, type SetupState } from 'gateway/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import Fa from 'svelte-fa'

    export let setupState: SetupState

    async function dismiss () {
        await api.dismissTutorial()
        await reloadServerInfo()
    }
</script>

<div class="getting-started-help border-secondary">
    <div class="d-flex align-items-center mb-3">
        <h2 class="mb-0">getting started</h2>
        <button class="btn btn-link ms-auto p-0 text-muted" onclick={dismiss}>Dismiss</button>
    </div>

    <ListGroup flush>
        <!-- eslint-disable-next-line svelte/no-target-blank -->
        <a href="https://warpgate.null.page/docs/" target="_blank" class="list-group-item list-group-item-action d-flex align-items-center">
            <Fa icon={faCircle} />
            <div class="item-text me-auto">
                <div>Check out the documentation</div>
            </div>
            <Fa icon={faExternalLink} />
        </a>

        <a href="/@warpgate/admin#/config/targets/create" class="list-group-item list-group-item-action d-flex align-items-center">
            <Fa icon={setupState.hasTargets ? faCircleCheck : faCircle} />
            <div class="item-text">
                <div>Add a target</div>
                <small>Targets are the servers and services that your users will connect to through Warpgate</small>
            </div>
        </a>

        <a href="/@warpgate/admin#/config/users/create" class="list-group-item list-group-item-action d-flex align-items-center">
            <Fa icon={setupState.hasUsers ? faCircleCheck : faCircle} />
            <div class="item-text">
                <div>Add a non-admin user</div>
                <small>Create separate non-admin user accounts for your users</small>
            </div>
        </a>
    </ListGroup>
</div>


<style lang="scss">
    .getting-started-help {
        margin-bottom: 3rem;
        border-top: 1px solid transparent;
        border-bottom: 1px solid transparent;
        padding: 1.5rem 0.5rem;

        h2 {
            font-family: 'Poppins';
            font-weight: 700;
        }

        .item-text {
            margin-left: 1rem;
        }
    }
</style>
