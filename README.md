# Traefik Plugin For Allowing Exceptions From Basic Auth

This Traefik plugin allows you to define exceptions for certain origin ips / ip ranges to override basic auth requirements. 
This works by defining a special user / passwords in Traefik's basic auth configuration.

## Sample Configuration

The following code snippet is a sample configuration for the dynamic file based provider, but as usual, this plugin should work with all other configuration providers as well.

```toml
[http]
  [http.routers]
    [http.routers.router0]
      entryPoints = ["http"]
      service = "service-foo"
      rule = "Path(`/foo`)"
      middlewares = ["except-auth", "test-auth"]

  [http.middlewares]
    [http.middlewares.except-auth.plugin.except-authbasic]
      allowIpList = ["127.0.0.1"]
      user = "user"
      password = "password"
      preventUser = true
    [http.middlewares.test-auth.basicauth]
      users = "user:$apr1$6Ktd55e3$9qaa6Dw9t70x90uQbZsts/,anotheruser:$apr1$cwugIdEJ$juXAPT2qb0sUroFEIucqz0"
      realm = "Test"
      removeHeader = true
```

## Limitations

Please note:

- This plugin does currently only look at the remote ip address and ignores e.g. the `X-Forwarded-For` header

## Configuration

This plugin supports the following configuration parameters:

- **allowIpList** List of strings containing the allowed ip addresses (e.g. `127.0.0.1`) and ip address ranges (e.g. `127.0.0.1/8`). Default: `[]`
- **user** Username of the basic auth user to be used for authentication. Default: `"""`
- **password** Password of the basic auth user to be used for authentication. Default: `"""`. Needs to be in plaintext!
- **preventUser** Disallows any request trying to authenticate with the above credentials not originating from any of the allowed ip addressed. Default: `false`