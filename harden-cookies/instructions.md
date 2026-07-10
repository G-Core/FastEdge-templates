In CDN resource configuration assign the application to `On response headers`.

If you want to harden just single cookie, specify its name in `COOKIE_NAME` parameter, or leave default value `*` to harden all cookies.

Specify which attributes you want to apply to the cookie(s):

- `Secure` (`SECURE` param)
- `HttpOnly` (`HTTPONLY` param)
- `SameSite=Strict` (`SAMESITE` param)

Please note if `SAMESITE` is set to `true` and the cookie already has `SameSite` attribute with value, different from `Strict`, it will be completely overwritten with `SameSite=Strict`.

Template source is available here: [FastEdge-templates/harden-cookies](https://github.com/G-Core/FastEdge-templates/tree/main/harden-cookies)
