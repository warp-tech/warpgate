projects := "warpgate warpgate-admin warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-database-protocols warpgate-protocol-ssh warpgate-protocol-mysql warpgate-protocol-http warpgate-core warpgate-sso"

run *ARGS:
    RUST_BACKTRACE=1 RUST_LOG=warpgate cd warpgate && cargo run -- --config ../config.yaml {{ARGS}}

fmt:
    for p in {{projects}}; do cargo fmt -p $p -v; done

fix *ARGS:
    for p in {{projects}}; do cargo fix -p $p {{ARGS}}; done

clippy *ARGS:
    for p in {{projects}}; do cargo cranky -p $p {{ARGS}}; done

test:
    for p in {{projects}}; do cargo test -p $p; done

yarn *ARGS:
    cd warpgate-web && yarn {{ARGS}}

migrate *ARGS:
    cargo run -p warpgate-db-migrations -- {{ARGS}}

lint:
    cd warpgate-web && yarn run lint

svelte-check:
    cd warpgate-web && yarn run check

openapi-all:
    cd warpgate-web && yarn openapi:schema:admin && yarn openapi:schema:gateway && yarn openapi:client:admin && yarn openapi:client:gateway

openapi:
    cd warpgate-web && yarn openapi:client:admin && yarn openapi:client:gateway

cleanup: (fix "--allow-dirty") (clippy "--fix" "--allow-dirty") fmt svelte-check lint

udeps:
    cargo udeps --all-targets
