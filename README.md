# i2p env-configurable docker
Docker `i2pd` daemon on Alpine Linux with auto config using env vars

Allows to specify i2p tunnels (client/server) providing key in env (or generating it automatically)

Available on `hub.docker.com` as: `darktool/i2p`

## env
- `CLIENT`: client tunnels definition, default undefined
  - `80:nginx:8080:KEY`
  - `80:nginx:8080`: new key created
  - `nginx:80`: new key created
- `HIDDEN_I2P`: server tunnels definition, default undefined
  - `TYPE:HOST:PORT:KEY`
- `BANDWIDTH`:
  - `X` (unlimited): good for servers or fast clients (default)
  - `P` (2048): good for slower client
  - `O` (256)
  - `L` (32)
- `SHARE`: forwarding traffic share limit, default 25%
- `LENGTH`: tunnels length, default 3
- `CONNECTIONS`: connections count, default 12
- `LOGLEVEL`: default `error`

## tunnel type
- `client`: for accessing remote as local docker via i2p
- `server`: to provide server tcp tunnel via i2p (similar to Tor Hidden Service)
- `http`: `server` + Host: HTTP header
- `socks` + `httpproxy`
- `udpclient` + `udpserver`
- `irc`

## exposes
- `4444/tcp`: http server
- `4447/tcp`: socks server
- `7070/tcp`: http control connection

## key management tools
These tools are available in docker
- `keygen`: generate and output key
  - usage: `docker run --rm darktool/i2p keygen`: make key and write to stdout, default key type 7 == `ED25519-SHA512` (`EDDSA-SHA512-ED25519`)
- `keyinfo`: output key info
  - usage: `echo $KEY | docker run --rm darktool/i2p keyinfo`: key info for base64-encoded i2p key

## key types
- `DSA-SHA1`: 0
- `ECDSA-SHA256-P256`: 1
- `ECDSA-SHA384-P384`: 2
- `ECDSA-SHA512-P521`: 3
- `RSA-SHA256-2048`: 4
- `RSA-SHA384-3072`: 5
- `RSA-SHA512-4096`: 6
- `EDDSA-SHA512-ED25519`: 7 
- `GOSTR3410_CRYPTO_PRO_A-GOSTR3411-256`: 9
- `GOSTR3410_TC26_A_512-GOSTR3411-512`: 10
- `RED25519-SHA512`: 11
- default: `ED25519-SHA512`
