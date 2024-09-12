
## api usage

> Most of the api format can be found from [openapi-schema](https://github.com/warp-tech/warpgate/blob/41b319d931bd7f064196e85ec62424d9aa434978/warpgate-web/src/gateway/lib/openapi-schema.json), and you can compare with the web access mode.

> The auth/login will return cookie, all of the following examples used this cookie
```bash
curl -vv -H "Content-Type: application/json" -k -XPOST -d '{"username": "admin", "password": "xxxxxxxx"}' https://warp.test.com/@warpgate/api/auth/login
......
< Connection: keep-alive                                                                    
< cache-control: must-revalidate,no-cache,no-store
< strict-transport-security: max-age=31536000
< set-cookie: warpgate-http-session=Z5pLMtLWt3h4Rv-CD9RGwdhe64XZDX42vk3_v19vJEQ; HttpOnly; Path=/; Max-Age=86400
```

| Topic | Intro | Method | API |
| :- | :- | :- | :- |
| login | auth login | POST | `POST /api/auth/login` |
| target | get all targets list <br> create target <br> delete target <br> grant target to role <br> revoke target from role | GET <br> POST <br> DELETE <br> POST <br> DELETE | `GET /api/targets` <br> `POST /api/targets` <br> `DELETE /api/targets/<target id>` <br> `POST /api/targets/<target id>/roles/<role id>` <br> `DELETE /api/targets/<target id>/roles/<role id>` |
| user | get all user list <br> create user <br> grant user to role <br> revoke user from role <br> delete user | GET <br> POST <br> POST <br> DELETE <br> DELETE | `GET /api/users` <br> `POST /api/users` <br> `POST /api/users/<user id>/roles/<role id>` <br> `DELETE /api/users/<user id>/roles/<role id>` <br> `DELETE /api/users/<user id>` |
| role | get all roles list <br> create role <br> delete role | GET <br> POST <br> DELETE | `GET /api/roles` <br> `POST /api/roles` <br> `DELETE /api/role/<role id>` |


> note: delete role in api is `role`, not `roles`


## examples

### login

```
curl -H "Content-Type: application/json" \
     -XPOST \
     -d '{"username": "admin", "password": "xxxxxxxx"}' \
     -k https://warp.test.com/@warpgate/api/auth/login
```

### target

#### get all targets

```
curl -H "Cookie: warpgate-http-session=Z5pLMtLWt3h4Rv-CD9RGwdhe64XZDX42vk3_v19vJEQ" \
     -k https://warp.test.com/@warpgate/admin/api/targets?search=mysql
```

#### create target

```
curl -s -H "Cookie: ......" \
     -H "Content-Type: application/json" \
     -XPOST \
     -d '{"name": "mysql-test", "options": {"host": "10.1.1.2", "port": 3306, "username": "admin", "password":"xxxxxxx", "kind":"MySql", "tls": {"mode":"Disabled","verify":false}}}' \
     -k 'https://warp.test.com/@warpgate/admin/api/targets'
```

#### delete target

```
curl -s -H "Cookie: ....." \
     -XDELETE \
     -k 'https://warp.test.com/@warpgate/admin/api/targets/7ae26355-0550-48bf-9fc5-d68d6a498da3'
```

#### grant target to role

```
curl -s -H "Cookie: ......" \
     -XPOST \
     -k 'https://warp.test.com/@warpgate/admin/api/targets/e1495f19-188d-4110-a235-b30ddf2b33fe/roles/5e65d7f6-f30c-4147-885b-1257d0922e20'
```

### user

#### get all users

```
curl -s -H "Cookie: ......" \
     -XGET \
     -k 'https://warp.test.com/@warpgate/admin/api/users'
```

#### create user

```
curl -s -H "Cookie: ......" -H "Content-Type: application/json" \
     -XPOST \
     -d '{"username":"user_read", "credentials":[{"hash":"xxxxxxx","kind":"Password"}], "credential_policy":{"ssh":[],"http":[],"mysql":null}}' \
     -k 'https://warp.test.com/@warpgate/admin/api/users'
```

#### grant user to role

```
curl -s -H "Cookie: ......" \
     -XPOST \
     -k 'https://warp.test.com/@warpgate/admin/api/users/e620d053-a2c6-469b-8595-962b2596a245/roles/5e65d7f6-f30c-4147-885b-1257d0922e20'
```

#### revoke user from role

```
curl -s -H "Cookie: ......" \
     -XDELETE \
     -k 'https://warp.test.com/@warpgate/admin/api/users/e620d053-a2c6-469b-8595-962b2596a245/roles/5e65d7f6-f30c-4147-885b-1257d0922e20'
```

#### delete user

```
curl -s -H "Cookie: ......" \
     -XDELETE \
     -k 'https://warp.test.com/@warpgate/admin/api/users/e620d053-a2c6-469b-8595-962b2596a245'
```

### role

#### get all roles list

```
curl -s -H "Cookie: ......" \
     -XGET \
     -k 'https://warp.test.com/@warpgate/admin/api/roles'
```

#### create role

```
curl -s -H "Cookie: ......" \
     -H "Content-Type: application/json" \
     -XPOST \
     -d '{"name":"warpgate:readonly"}' \
     -k 'https://warp.test.com/@warpgate/admin/api/roles'
```

#### delete role

> note: delete role in api is `role`, not `roles`

```
curl -s -H "Cookie: ......" 、
     -XDELETE \
     -k 'https://warp.test.com/@warpgate/admin/api/role/3f430429-77ef-47c3-ba0d-80faacbc0369'
```
