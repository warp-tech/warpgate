<script lang="ts">
    import type { BootstrapThemeColor } from 'gateway/lib/api'
    import { getCSSColorFromThemeColor } from './helpers'

    export let color: BootstrapThemeColor | ''
</script>

<div class="circle" style="background-color: {getCSSColorFromThemeColor(color || undefined)})"></div>

<style lang="scss">
    .circle {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        flex-shrink: 0;
    }
</style>
