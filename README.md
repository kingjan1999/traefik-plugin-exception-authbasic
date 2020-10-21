# Traefik Plugin For Allowing Exceptions From Basic Auth

This Traefik plugin allows you to define exceptions for certain origin ips / ip ranges or requests with specific headers to override basic auth requirements. 
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
      allowIPList = ["127.0.0.1"]
      user = "user"
      password = "password"
      preventUser = true
      headers = {"X-Very-Secret" = "totallysecret"}
    [http.middlewares.test-auth.basicauth]
      users = "user:$apr1$6Ktd55e3$9qaa6Dw9t70x90uQbZsts/,anotheruser:$apr1$cwugIdEJ$juXAPT2qb0sUroFEIucqz0"
      realm = "Test"
      removeHeader = true
```

*Please note:* The middleware for this plugin needs to be loaded before the basic auth middleware (as seen above).

## Configuration

This plugin supports the following configuration parameters:

- **allowIPList** List of strings containing the allowed ip addresses (e.g. `127.0.0.1`) and ip address ranges (e.g. `127.0.0.1/8`). Default: `[]`
- **user** Username of the basic auth user to be used for authentication. Default: `"""`
- **password** Password of the basic auth user to be used for authentication. Default: `"""`. Needs to be in plaintext!
- **preventUser** Disallows any request trying to authenticate with the above credentials not originating from any of the allowed ip addressed. Default: `false`
- **ipHeaders** Allows you to specify additional headers (e.g. `X-Forwarded-For`, `X-Real-IP`) to use as sources besides the requests remote ip. Please note: If any ip address can be found in one of these headers, the requests remote ip is ignored. Multiple ips in a header (e.g. `127.0.0.1,127.0.0.2`) are treated equally. Using this feature is highly discouraged. Please ensure that these headers are not set by end users. Default: `[]`
- **headers** Map of headers and their expected value which override the basic auth requirement as well (so requests with these headers do not require basic auth). Use `*` as wildcard value. Please note: This is or-chained with the ip based rules. Default: `{}    ` 