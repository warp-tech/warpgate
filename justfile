projects := "warpgate warpgate-admin warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-protocol-ssh"

fmt:
    for p in {{projects}}; do cargo fmt -p $p -v; done

fix *ARGS:
    for p in {{projects}}; do cargo fix -p $p {{ARGS}}; done

clippy *ARGS:
    for p in {{projects}}; do cargo clippy -p $p {{ARGS}}; done

watch:
    cd warpgate-admin/frontend/ && yarn watch

svelte-check:
    cd warpgate-admin/frontend/ && yarn run check

openapi:
    cd warpgate-admin/frontend/ && yarn openapi-schema && yarn openapi-client

cleanup: (fix "--allow-dirty") (clippy "--fix" "--allow-dirty") fmt
