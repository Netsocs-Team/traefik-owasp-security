# Traefik OWASP Security Headers Plugin

![](./img/icon.jpg)

A Traefik middleware plugin that automatically adds a comprehensive set of [OWASP-recommended](https://owasp.org/www-project-secure-headers/) security headers to HTTP responses and enforces secure cookie attributes.

> [!NOTE]
> This repository is not officially endorsed or maintained by OWASP. It is a community-driven project that aims to implement security headers based on OWASP's recommendations and best practices. While we strive to follow OWASP guidelines, always verify the configurations for your specific use case.
>
> For official OWASP resources, please visit: https://owasp.org.

## Features

-   Adds strict security headers to all HTTP responses, including:
    -   `Strict-Transport-Security`
    -   `X-Content-Type-Options`
    -   `X-Frame-Options`
    -   `X-XSS-Protection`
    -   `Referrer-Policy`
    -   `Content-Security-Policy`
    -   `Permissions-Policy`
    -   `X-Permitted-Cross-Domain-Policies`
    -   `Cross-Origin-Opener-Policy`
    -   `Cross-Origin-Resource-Policy`
    -   `Cross-Origin-Embedder-Policy`
    -   `Cache-Control`
    -   `Pragma`
    -   `Expect-CT`
    -   `Feature-Policy`
    -   and more
-   Removes or hides sensitive headers like `Server` and `X-Powered-By`.
-   Automatically appends `HttpOnly`, `Secure`, and `SameSite=Lax` attributes to cookies (configurable).
-   Easy to configure and integrate with Traefik.

## Installation

1. Add the plugin to your Traefik static configuration:

```yaml
experimental:
    plugins:
        traefik-owasp-security:
            moduleName: "github.com/Netsocs-Team/traefik-owasp-security"
            version: "v0.1.0"
```

2. Reference the plugin in your middleware configuration:

```yaml
http:
    middlewares:
        owasp-security-headers:
            plugin:
                traefik-owasp-security:
                    # Optional configuration
                    disableCookieHTTPOnly: false
                    disableCookieSecure: false
                    disableCookieSameSite: false
```

3. Attach the middleware to your routers as needed.

## Configuration

| Option                | Type | Default | Description                          |
| --------------------- | ---- | ------- | ------------------------------------ |
| disableCookieHTTPOnly | bool | false   | Disable adding `HttpOnly` to cookies |
