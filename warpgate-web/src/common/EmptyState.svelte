<script lang="ts">
    export let title: string
    export let hint = ''
</script>

<div class="empty-state">
    <h2>{title}</h2>
    {#if hint}
        <p class="text-muted">{hint}</p>
    {/if}
</div>

<style lang="scss">
    .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        width: 50%;
        min-width: 200px;
        text-align: center;
        margin: 4rem auto;
    }

    h2 {
        font-family: 'Poppins';
        color: var(--bs-secondary-color);
    }

    p {
        font-size: .9rem;
    }
</style>
