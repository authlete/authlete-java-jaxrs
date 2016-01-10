Authlete Library for JAX-RS (Java)
==================================

Overview
--------

This library provides utility classes to make it easy for developers
to implement an authorization server which supports [OAuth 2.0][1] and
[OpenID Connect][2]. [java-oauth-server][3] is an authorization server
implementation which uses this library.

This library is written using JAX-RS 2.0 API and [authlete-java-common][4]
library. JAX-RS is _The Java API for RESTful Web Services_. JAX-RS
2.0 API is standardized by [JSR 339][5] and contained in Java EE 7.
On the other hand, authlete-java-common library is another Authlete's
open source library which provides classes to communicate with
[Authlete Web APIs][6].

[Authlete][7] is an OAuth 2.0 & OpenID Connect implementation on _cloud_
([overview][8]). You can build a _DB-less_ authorization server by using
Authlete because authorization data (e.g. access tokens), settings of
authorization servers and settings of client applications are stored in
the Authlete server on cloud.


License
-------

Apache License, Version 2.0


Maven
-----

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>authlete-java-jaxrs</artifactId>
    <version>1.0</version>
</dependency>
```


Source Code
-----------

    https://github.com/authlete/authlete-java-jaxrs


JavaDoc
-------

    http://authlete.github.io/authlete-java-jaxrs


Description
-----------

Endpoints that an authorization server is expected to expose are an
[authorization endpoint][9] and a [token endpoint][10]. This library
provides utility classes to implement these endpoints.


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
parameters and to call the `handle()` method with the instance.
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

// Implementation of AuthleteApi interface. See authlete-java-common.
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
`AuthorizationResponse` class which is a response from Authlete's
`/api/auth/authorization` Web API. The instance contains information
that will be needed in generating an authorization page.

```java
Response generateAuthorizationPage(AuthorizationResponse info);
```

See the [JavaDoc][11] and the reference implementation
([java-oauth-server][3]) for details.


### Authorization Decision Endpoint

An authorization page displays information about an authorization request
such as the name of the client application and requested permissions. An
end-user checks the information and decides either to authorize or to deny
the request. An authorization server receives the decision and returns a
response according to the decision. This means that an authorization server
must have an endpoint that receives the decision in addition to the
authorization endpoint.

`AuthorizationDecisionHandler` is a class to process the decision.
The class has `handle()` method as does `AuthorizationRequestHandler`.
Also, its constructor requires an implementation of
`AuthorizationDecisionHandlerSpi` interface as does the constructor
of `AuthorizationRequestHandler`.


### Token Endpoint

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

In summary, a flow in a token endpoint implentation will look like
the following.

```java
// Request parameters of a token request.
MultivaluedMap<String, String> parameters = ...;

// The value of Authorization header.
String authorization = ...;

// Implementation of AuthleteApi interface. See authlete-java-common.
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


Summary
-------

This library makes it easy to implement an authorization server that
supports OAuth 2.0 and OpenID Connect. See the [JavaDoc][11] and the
reference implementation ([java-oauth-server][3]) for details.


Support
-------

[Authlete, Inc.](https://www.authlete.com/)
support@authlete.com


[1]: http://tools.ietf.org/html/rfc6749
[2]: http://openid.net/connect/
[3]: https://github.com/authlete/java-oauth-server
[4]: https://github.com/authlete/authlete-java-common
[5]: https://jcp.org/en/jsr/detail?id=339
[6]: https://www.authlete.com/documents/apis
[7]: https://www.authlete.com/
[8]: https://www.authlete.com/documents/overview
[9]: https://tools.ietf.org/html/rfc6749#section-3.1
[10]: https://tools.ietf.org/html/rfc6749#section-3.2
[11]: http://authlete.github.io/authlete-java-jaxrs