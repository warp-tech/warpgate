<script lang="ts">
    import type { JsonSchema } from 'admin/lib/jsonSchema'
    import SchemaNode from 'admin/lib/SchemaNode.svelte'
    import { setCurrentSidebarSubtitle } from 'common/sidebarState.svelte'
    import { link } from 'svelte-spa-router'
    import schema from '../../../../gitops-schema.json'

    const root: JsonSchema = schema

    setCurrentSidebarSubtitle(() => 'Config format')
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>gitops config format</h1>
        <a class="ms-auto" href="/config/gitops" use:link>GitOps settings</a>
    </div>

    <p class="text-muted">
        A config file holds one or more YAML documents, one resource each.
        Select a resource kind to see its fields.
    </p>

    <SchemaNode schema={root} {root} />
</div>
