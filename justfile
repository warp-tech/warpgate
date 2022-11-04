projects := "warpgate warpgate-admin warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-database-protocols warpgate-protocol-ssh warpgate-protocol-mysql warpgate-protocol-http warpgate-core warpgate-sso"

features := "sqlite,postgres,mysql"

run *ARGS:
    RUST_BACKTRACE=1 RUST_LOG=warpgate cargo run --features {{features}} -- --config config.yaml {{ARGS}}

fmt:
    for p in {{projects}}; do cargo fmt --features {{features}} -p $p -v; done

fix *ARGS:
    for p in {{projects}}; do cargo fix --features {{features}} -p $p {{ARGS}}; done

clippy *ARGS:
    for p in {{projects}}; do cargo cranky --features {{features}} -p $p {{ARGS}}; done

test:
    for p in {{projects}}; do cargo test --features {{features}} -p $p; done

yarn *ARGS:
    cd warpgate-web && yarn {{ARGS}}

migrate *ARGS:
    cargo run --features {{features}} -p warpgate-db-migrations -- {{ARGS}}

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
    cargo udeps --features {{features}} --all-targets
