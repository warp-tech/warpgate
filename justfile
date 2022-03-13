projects := "warpgate warpgate-admin warpgate-cli warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-protocol-ssh"

fmt:
    for p in {{projects}}; do cargo fmt -p $p -v; done

clippy:
    for p in {{projects}}; do cargo +nightly clippy -p $p; done

watch:
    cd warpgate-admin/frontend/ && yarn watch

openapi:
    cd warpgate-admin/frontend/ && yarn openapi-schema && yarn openapi-client
