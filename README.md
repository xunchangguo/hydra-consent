# hydra-consent
ory hydra login/consent app for demo

This is a simple consent app for Hydra written in Go. It uses the Hydra SDK.

```
docker run -d \
  --name hydra \
  -p 9000:4444 \
  -p 9001:4445 \
  -e SYSTEM_SECRET=adminadminadminadminadmin \
  -e FORCE_ROOT_CLIENT_CREDENTIALS='rootadmin:rootadminpass' \
  -e DATABASE_URL=memory \
  -e OAUTH2_ISSUER_URL=https://172.28.105.108:9000/ \
  -e OAUTH2_CONSENT_URL=https://172.28.105.97:3000/consent \
  -e OAUTH2_LOGIN_URL=https://172.28.105.97:3000/login \
  -e HTTPS_TLS_CERT_PATH=/server.crt \
  -e HTTPS_TLS_KEY_PATH=/key.pem -v $(pwd)/server.crt:/server.crt -v $(pwd)/key.pem:/key.pem \
  docker.io/oryd/hydra:v1.0.0-beta.9 serve all
```

register client
```
 docker run --rm -it \
  oryd/hydra:v1.0.0-beta.9 \
  clients create --skip-tls-verify \
    --id clientid \
	--endpoint https://172.28.105.108:9001 \
    --grant-types authorization_code,refresh_token,client_credentials,implicit \
    --response-types token,code,id_token \
    --scope openid,offline,photos.read \
    --callbacks https://172.28.105.97:3000/callback
```

it will print client id and client secret
```
OAuth2 client id: clientid
OAuth2 client secret: OVpS.SSppeoMJDlKqevSngsih8
```
In another console, run

```
hydra-consent-app-go
```
run toker user for test
```
 docker run --rm -it \
  -p 9010:9010 \
  oryd/hydra:v1.0.0-beta.9 \
  token user --skip-tls-verify \
    --port 9010 \
	--endpoint https://172.28.105.108:9001 \
    --auth-url https://172.28.105.108:9000/oauth2/auth \
    --token-url https://172.28.105.108:9000/oauth2/token \
    --client-id <client id>\
    --client-secret <client secret> \
	--redirect https://172.28.105.97:3000/callback \
    --scope openid,offline,photos.read
```

open browser view http://<host ip>:9010 
