projects := "warpgate warpgate-admin warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-database-protocols warpgate-protocol-ssh warpgate-protocol-mysql warpgate-protocol-postgres warpgate-protocol-http warpgate-core warpgate-sso"

run $RUST_BACKTRACE='1' *ARGS='run':
     cargo run --all-features -- --config config.yaml {{ARGS}}

fmt:
    for p in {{projects}}; do cargo fmt -p $p -v; done

fix *ARGS:
    for p in {{projects}}; do cargo fix --all-features -p $p {{ARGS}}; done

clippy *ARGS:
    for p in {{projects}}; do cargo cranky --all-features -p $p {{ARGS}}; done

test:
    for p in {{projects}}; do cargo test --all-features -p $p; done

npm *ARGS:
    cd warpgate-web && npm {{ARGS}}

npx *ARGS:
    cd warpgate-web && npx {{ARGS}}

migrate *ARGS:
    cargo run --all-features -p warpgate-db-migrations -- {{ARGS}}

lint *ARGS:
    cd warpgate-web && npm run lint {{ARGS}}

svelte-check:
    cd warpgate-web && npm run check

openapi-all:
    cd warpgate-web && npm run openapi:schema:admin && npm run openapi:schema:gateway && npm run openapi:client:admin && npm run openapi:client:gateway

openapi:
    cd warpgate-web && npm run openapi:client:admin && npm run openapi:client:gateway

cleanup: (fix "--allow-dirty") (clippy "--fix" "--allow-dirty") fmt svelte-check lint

udeps:
    cargo udeps --all-features --all-targets
