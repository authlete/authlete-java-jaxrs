Authlete Library for JAX-RS (Java)
==================================

Overview
--------

This library provides utility classes to make it easy for developers
to implement an authorization server which supports [OAuth 2.0][1] and
[OpenID Connect][2] and a resource server.

This library is written using JAX-RS 2.0 API and [authlete-java-common][4]
library. JAX-RS is _The Java API for RESTful Web Services_. JAX-RS 2.0
API has been standardized by [JSR 339][5] and it is included in Java EE 7.
On the other hand, authlete-java-common is another Authlete's open source
library which provides classes to communicate with [Authlete Web APIs][6].

[Authlete][7] is a cloud service that provides an implementation of OAuth
2.0 & OpenID Connect ([overview][8]). You can build a _DB-less_ authorization
server by using Authlete because authorization data (e.g. access tokens),
settings of authorization servers and settings of client applications are
stored in the Authlete server on cloud.

[java-oauth-server][3] is an authorization server implementation which
uses this library. It implements not only an authorization endpoint and
a token endpoint but also a JWK Set endpoint, a configuration endpoint
and a revocation endpoint. [java-resource-server][19] is a resource
server implementation which also uses this library. It supports a
[userinfo endpoint][20] defined in [OpenID Connect Core 1.0][13] and
includes an example of a protected resource endpoint, too. Use these
reference implementations as a starting point of your own implementations
of an authorization server and a resource server.


License
-------

  Apache License, Version 2.0


Maven
-----

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>authlete-java-jaxrs</artifactId>
    <version>2.0</version>
</dependency>
```


Source Code
-----------

  <code>https://github.com/authlete/authlete-java-jaxrs</code>


JavaDoc
-------

  <code>http://authlete.github.io/authlete-java-jaxrs</code>


Description
-----------

An authorization server is expected to expose the following endpoints.

  1. Authorization endpoint ([RFC 6749, 3.1][9])
  2. Token endpoint ([RFC 6749, 3.2][10])

This library provides utility classes to implement these endpoints.
In addition, utility classes for endpoints listed below are included,
too.

  3. JWK Set endpoint ([OpenID Connect Core 1.0][13])
  4. Configuration endpoint ([OpenID Connect Discovery 1.0][12])
  5. Revocation endpoint ([RFC 7009][14])
  6. UserInfo endpoint ([OpenID Connect Core 1.0][13])


#### Authorization Endpoint

`AuthorizationRequestHandler` is a class to process an authorization
request from a client application. The class has `handle()` method
which takes an instance of `MultivaluedMap<String, String>` class
that holds request parameters of an authorization request.

```java
public Response handle(MultivaluedMap<String, String> parameters)
    throws WebApplicationException
```

An implementation of authorization endpoint can delegate the task to
process an authorization request to the `handle()` method.

If you are using JAX-RS, it is easy to obtain an instance of
`MultivaluedMap<String, String>` instance containing request
parameters and call the `handle()` method with the instance.
But, the point exists at another different place. You are required
to prepare an implementation of `AuthorizationRequestHandlerSpi`
interface and pass it to the constructor of `AuthorizationRequestHandler`
class.

`AuthorizationRequestHandlerSpi` is _Service Provider Interface_ that
you are required to implement in order to control the behavior of the
`handle()` method of `AuthorizationRequestHandler`.

In summary, a flow in an authorization endpoint implementation will
look like the following.

```java
// Request parameters of an authorization request.
MultivaluedMap<String, String> parameters = ...;

// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Your implementation of AuthorizationRequestHandlerSpi interface.
AuthorizationRequestHandlerSpi spi = ...;

// Create an instance of AuthorizationRequestHandler class.
AuthorizationRequestHandler handler =
    new AuthorizationRequestHandler(api, spi);

// Delegate the task to process the authorization request to the handler.
Response response = handler.handle(parameters);

// Return the response to the client application.
return response;
```

The most important method defined in `AuthorizationRequestHandlerSpi`
interface is `generateAuthorizationPage()`. It is called to generate
an authorization page. The method receives an instance of
`AuthorizationResponse` class which represents a response from Authlete's
`/api/auth/authorization` Web API. The instance contains information
that will be needed in generating an authorization page.

```java
Response generateAuthorizationPage(AuthorizationResponse info);
```

See the [JavaDoc][11] and the reference implementation
([java-oauth-server][3]) for details.


#### Authorization Decision Endpoint

An authorization page displays information about an authorization request
such as the name of the client application and requested permissions. An
end-user checks the information and decides either to authorize or to deny
the request. An authorization server receives the decision and returns a
response according to the decision. Therefore, an authorization server
must have an endpoint that receives the decision by an end-user in addition
to the authorization endpoint.

`AuthorizationDecisionHandler` is a class to process the decision.
The class has `handle()` method as does `AuthorizationRequestHandler`.
Also, its constructor requires an implementation of
`AuthorizationDecisionHandlerSpi` interface as does the constructor
of `AuthorizationRequestHandler`.


#### Token Endpoint

`TokenRequestHandler` is a class to process a token request from a client
application. The class has `handle()` method which takes two arguments of
`MultivaluedMap<String, String>` and `String`. The `MultivaluedMap`
argument represents request parameters and the `String` argument is the
value of `Authorization` header in the token request.

```java
public Response handle(
    MultivaluedMap<String, String> parameters, String authorization)
    throws WebApplicationException
```

An implementation of token endpoint can delegate the task to process a
token request to the `handle()` method.

The constructor of `TokenRequestHandler` takes an implementation of
`TokenRequestHandlerSpi` interface as does the constructor of
`AuthorizationRequestHandler`.

In summary, a flow in a token endpoint implementation will look like
the following.

```java
// Request parameters of a token request.
MultivaluedMap<String, String> parameters = ...;

// The value of Authorization header.
String authorization = ...;

// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Your implementation of TokenRequestHandlerSpi interface.
TokenRequestHandlerSpi spi = ...;

// Create an instance of TokenRequestHandler class.
TokenRequestHandler handler = new TokenRequestHandler(api, spi);

// Delegate the task to process the token request to the handler.
Response response = handler.handle(parameters, authorization);

// Return the response to the client application.
return response;
```


#### JWK Set Endpoint

An OpenID Provider is required to expose its JSON Web Key Set document
(JWK Set) so that client application can (1) verify signatures by the
OpenID Provider and (2) encrypt their requests to the OpenID Provider.

`JwksRequestHandler` is a class to process a request to such an
endpoint. The class does not require any SPI implementation, so its
usage is simple.

```java
// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Create an instance of JwksRequestHandler class.
JwksRequestHandler handler = new JwksRequestHandler(api);

// Delegate the task to process a request.
Response response = handler.handle();

// Return the response to the client application.
return response;
```

Furthermore, `BaseJwksEndpoint` class makes the task incredibly easier.
The following is an example of a complete implementation of a JWK Set
endpoint. The `handle()` method of `BaseJwksEndpoint` internally uses
`JwksRequestHandler`.

```java
@Path("/api/jwks")
public class JwksEndpoint extends BaseJwksEndpoint
{
    @GET
    public Response get()
    {
        // Handle the JWK Set request.
        return handle(AuthleteApiFactory.getDefaultApi());
    }
}
```


#### Configuration Endpoint

An OpenID Provider that supports [OpenID Connect Discovery 1.0][12]
must provide an OpenID Provider configuration endpoint that returns
its configuration information in a JSON format. Details about the
format are described in [3. OpenID Provider Metadata][15] in OpenID
Connect Discovery 1.0.

`ConfigurationRequestHandler` is a class to process a request to
such a configuration endpoint. The class does not require any SPI
implementation, so its usage is simple.

```java
// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Create an instance of ConfigurationRequestHandler class.
ConfigurationRequestHandler handler = new ConfigurationRequestHandler(api);

// Delegate the task to process a request.
Response response = handler.handle();

// Return the response to the client application.
return response;
```

Furthermore, `BaseConfigurationEndpoint` class makes the task incredibly
easier. The following is an example of a complete implementation of an
OpenID Provider configuration endpoint. The `handle()` method of
`BaseConfigurationEndpoint` internally uses `ConfigurationRequestHandler`.

```java
@Path("/.well-known/openid-configuration")
public class ConfigurationEndpoint extends BaseConfigurationEndpoint
{
    @GET
    public Response get()
    {
        // Handle the configuration request.
        return handle(AuthleteApiFactory.getDefaultApi());
    }
}
```

Note that the URI of a configuration endpoint is defined in
[4.1. OpenID Provider Configuration Request][16] in OpenID Connect
Discovery 1.0. In short, the URI must be:

    Issuer Identifier + /.well-known/openid-configuration

_Issuer Identifier_ is a URL to identify an OpenID Provider, For example,
`https://example.com`. For details about Issuer Identifier, see `issuer`
in [3. OpenID Provider Meatadata][15] (OpenID Connect Discovery 1.0)
and `iss` in [2. ID Token][17] (OpenID Connect Core 1.0).


#### Revocation Endpoint

An authorization server may expose an endpoint to revoke access tokens
and/or refresh tokens. [RFC 7009][18] is the specification about such
a revocation endpoint.

`RevocationRequestHandler` is a class to process a revocation request.
The class has `handle()` method which takes two arguments of
`MultivaluedMap<String, String>` and `String`. The `MultivaluedMap`
argument represents request parameters and the `String` argument is
the value of `Authorization` header in the revocation request.

```java
public Response handle(
    MultivaluedMap<String, String> parameters, String authorization)
    throws WebApplicationException
```

An implementation of revocation endpoint can delegate the task to
process a revocation request to the `handle()` method. Below is an
example of the `handle()` method.

```java
// Request parameters of a revocation request.
MultivaluedMap<String, String> parameters = ...;

// The value of Authorization header.
String authorization = ...;

// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Create an instance of RevocationRequestHandler class.
RevocationRequestHandler handler = new RevocationRequestHandler(api);

// Delegate the task to process the revocation request to the handler.
Response response = handler.handle(parameters, authorization);

// Return the response to the client application.
return response;
```

Furthermore, `BaseRevocationEndpoint` class makes the task incredibly
easier. The following is an example of a complete implementation of a
revocation endpoint. The `handle()` method of `BaseRevocationEndpoint`
internally uses `RevocationRequestHandler`.

```java
@Path("/api/revocation")
public class RevocationEndpoint extends BaseRevocationEndpoint
{
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response post(
            @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
            MultivaluedMap<String, String> parameters)
    {
        // Handle the revocation request.
        return handle(AuthleteApiFactory.getDefaultApi(), parameters, authorization);
    }
}
```


#### UserInfo Endpoint

A userinfo endpoint is a protected resource endpoint that returns
user information in JSON or [JWT][21] format. The behavior of this
endpoint is described in [5.3. UserInfo Endpoint][20] in
[OpenID Connect Core 1.0][13].

`UserInfoRequestHandler` is a class to process a userinfo request.
The class has `handle(String)` method which takes an access token.
An implementation of userinfo endpoint can delegate the task to
process a userinfo request to the `handle()` method.

The constructor of `UserInfoRequestHandler` class requires an
implementation of `UserInfoRequestHandlerSpi` to control the
implementation-specific behaviors. The main purpose of the SPI
class is to collect claim values that will be embedded in a
response from a userinfo endpoint.

The following code snippet shows the usage of `UserInfoRequestHandler`.

```java
// Implementation of AuthleteApi interface.
// See https://github.com/authlete/authlete-java-common for details.
AuthleteApi api = ...;

// Implementation of UserInfoRequestHandlerSpi interface.
UserInfoRequestHandlerSpi spi = ...;

// Create an instance of UserInfoRequestHandler class.
UserInfoRequestHandler handler = new UserInfoRequestHandler(api, spi);

// Access token contained in a userinfo request.
String accessToken = ...;

// Delegate the task to process the userinfo request to the handler.
Response response = handler.handle(accessToken);

// Return the response to the client application.
return response;
```

Furthermore, `BaseUserInfoEndpoint` class makes the task incredibly
easier. The following is an example of an implementation of a
userinfo endpoint. The `handle()` method of `BaseUserInfoEndpoint`
internally uses `UserInfoRequestHandler`. Note that a userinfo
endpoint must accept an access token as a Bearer Token ([RFC 6750][22]).

```java
@Path("/api/userinfo")
public class UserInfoEndpoint extends BaseUserInfoEndpoint
{
    @GET
    public Response get(
            @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
            @QueryParam("access_token") String accessToken)
    {
        return handle(extractAccessToken(authorization, accessToken));
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response post(
            @HeaderParam(HttpHeaders.AUTHORIZATION) String authorization,
            @FormParam("access_token") String accessToken)
    {
        return handle(extractAccessToken(authorization, accessToken));
    }

    private Response handle(String accessToken)
    {
        return handle(AuthleteApiFactory.getDefaultApi(),
                new UserInfoRequestHandlerSpiImpl(), accessToken);
    }
}
```


Summary
-------

This library makes it easy to implement an authorization server that
supports OAuth 2.0 and OpenID Connect and a resource server. See the
[JavaDoc][11] and the reference implementations ([java-oauth-server][3]
and [java-resource-server][19]) for details.


See Also
--------

- [Authlete][7] - Authlete Home Page
- [java-oauth-server][3] - Authorization Server Implementation
- [java-resource-server][19] - Resource Server Implementation
- [authlete-java-common][4] - Authlete Common Library for Java


Support
-------

[Authlete, Inc.][7]<br/>
support@authlete.com


[1]: http://tools.ietf.org/html/rfc6749
[2]: http://openid.net/connect/
[3]: https://github.com/authlete/java-oauth-server
[4]: https://github.com/authlete/authlete-java-common
[5]: https://jcp.org/en/jsr/detail?id=339
[6]: https://www.authlete.com/documents/apis
[7]: https://www.authlete.com/
[8]: https://www.authlete.com/documents/overview
[9]: http://tools.ietf.org/html/rfc6749#section-3.1
[10]: http://tools.ietf.org/html/rfc6749#section-3.2
[11]: http://authlete.github.io/authlete-java-jaxrs
[12]: http://openid.net/specs/openid-connect-discovery-1_0.html
[13]: http://openid.net/specs/openid-connect-core-1_0.html
[14]: http://tools.ietf.org/html/rfc7009
[15]: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
[16]: http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
[17]: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
[18]: http://tools.ietf.org/html/rfc7009
[19]: https://github.com/authlete/java-resource-server
[20]: http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
[21]: http://tools.ietf.org/html/rfc7519
[22]: http://tools.ietf.org/html/rfc6750
