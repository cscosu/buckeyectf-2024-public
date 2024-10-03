## About

Author: `mbund`

`web` `hard`

Rate limit bypass

> The dojo stores many riches. Can you make it through the gauntlet?

## Solve

1. The game random number generator is seeded with the game id, which is visible in the jwt
2. The ratelimiter can be beat by specifying a header: https://github.com/go-chi/httprate/blob/ae11543f78101c85ceaa644402e70e67964d001c/httprate.go#L52-L74. Traefik is configured to overwrite X-Forwarded-For but will allow the other headers in.

The full solve is scripted in `solve.go`

```
go run solve.go
```
