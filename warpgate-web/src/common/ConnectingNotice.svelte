<script lang="ts">
    import InfoBox from 'common/InfoBox.svelte'

    // Opening a session is usually quick; only a target held at the approval
    // gate takes long enough for this to be worth reading.
    let visible = $state(false)

    $effect(() => {
        const timer = setTimeout(() => {
            visible = true
        }, 2000)
        return () => clearTimeout(timer)
    })
</script>

{#if visible}
    <div class="mx-3 mt-3">
        <InfoBox>
            Connecting. If this target needs administrator approval, the session
            will start once an administrator approves it.
        </InfoBox>
    </div>
{/if}
