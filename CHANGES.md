CHANGES
=======

2.19 (2019-08-24)
-----------------

- `AuthleteApiImpl` class
    * Implemented `registerRequestObject(RequestObjectRequest)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.49 to 2.50.


2.18 (2019-07-12)
-----------------

- `AuthleteApiCaller` class
    * Added some parameters to the arguments of `callDeviceComplete(String userCode, String subject, DeviceCompleteRequest.Result result, Property[] properties, String[] scopes, String errorDescription, URI errorUri)` method for ID token generation.

- `BaseEndpoint` class
    * Added `takeAttribute(HttpSession session, String key)` method.

- New classes
    * `BaseDeviceAuthorizationEndpoint` class
    * `BaseDeviceCompleteEndpoint` class
    * `BaseDeviceVerificationEndpoint` class
    * `DeviceAuthorizationPageModel` class
    * `DeviceAuthorizationRequestHandler` class
    * `DeviceCompleteRequestHandler` class
    * `DeviceVerificationPageModel` class
    * `DeviceVerificationRequestHandler` class
    * `DeviceCompleteRequestHandlerSpi` class
    * `DeviceCompleteRequestHandlerSpiAdapter` class
    * `DeviceVerificationRequestHandlerSpi` class
    * `DeviceVerificationRequestHandlerSpiAdapter` class

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.41 to 2.49.


2.17 (2019-05-30)
-----------------

- `AuthleteApiCaller` class
    * Added `callClientRegistration(String json)` method.
    * Added `callClientRegistration(String json, String initialAccessToken)` method.
    * Added `callClientRegistrationGet(String clientId, String registrationAccessToken)` method.
    * Added `callClientRegistrationUpdate(String clientId, String json, String registrationAccessToken)` method.
    * Added `callClientRegistrationDelete(String clientId, String registrationAccessToken)` method.

- `ResponseUtil` class
    * Added `created(String entity)` method.

- New classes
    * `BaseClientRegistrationEndpoint` class
    * `ClientRegistrationRequestHandler` class

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.36 to 2.41.


2.16 (2019-03-05)
-----------------

- `BackchannelAuthenticationRequestHandler` class
    * Modified some parts according the change to `BackchannelAuthenticationRequestHandlerSpi` interface.

- `BackchannelAuthenticationRequestHandlerSpi` interface
    * Added a `BackchannelAuthenticationIssueResponse` parameter to the arguments of `startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes)` method.

- `BackchannelAuthenticationRequestHandlerAdapter` class
    * Modified `startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes)` method according the change to `BackchannelAuthenticationRequestHandlerSpi` interface.


2.15 (2019-02-28)
-----------------

- `AuthleteApiCaller` class
    * Added error description and error URI support to `callBackchannelAuthenticationComplete(String, String, Result, long, String, Map<String, Object>, Property[], String[])` method.

- `BackchannelAuthenticationCompleteRequestHandler` class
    * Added error description and error URI support.

- `BackchannelAuthenticationCompleteRequestHandlerSpi` interface
    * Added `getErrorDescription()` method.
    * Added `getErrorUri()` method.

- `BackchannelAuthenticationCompleteRequestHandlerSpiAdapter` class
    * Implemented `getErrorDescription()` method.
    * Implemented `getErrorUri()` method.


2.14 (2019-01-17)
-----------------

- `BackchannelAuthenticationRequestHandler` class
    * Updated the implementation of `handleUserIdentification(BackchannelAuthenticationResponse)`
      method to validate the `binding_message` request parameter.

- `BackchannelAuthenticationRequestHandlerSpi` interface
    * Added `isValidBindingMessage(String)` method.

- `BackchannelAuthenticationRequestHandlerSpiAdapter` class
    * Implemented `isValidBindingMessage(String)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.33 to 2.36.


2.13 (2019-01-09)
-----------------

- `AuthleteApiCaller` class
    * Added `callBackchannelAuthentication(MultivaluedMap<String, String>, String, String, String, String[] clientCertificatePath)` method.
    * Added `backchannelAuthenticationFail(String, BackchannelAuthenticationFailRequest.Reason)` method.
    * Added `callBackchannelAuthenticationIssue(String)` method.
    * Added `callBackchannelAuthenticationComplete(String, String, Result, long, String, Map<String, Object>, Property[], String[])` method.

- `AuthleteApiImpl` class
    * Implemented `backchannelAuthentication(BackchannelAuthenticationRequest)` method.
    * Implemented `backchannelAuthenticationIssue(BackchannelAuthenticationIssueRequest)` method.
    * Implemented `backchannelAuthenticationFail(BackchannelAuthenticationFailRequest)` method.
    * Implemented `backchannelAuthenticationComplete(BackchannelAuthenticationCompleteRequest)` method.

- New classes and interfaces
    * `BackchannelAuthenticationCompleteRequestHandler` class
    * `BackchannelAuthenticationCompleteRequestHandlerSpi` interface
    * `BackchannelAuthenticationCompleteRequestHandlerSpiAdapter` class
    * `BackchannelAuthenticationRequestHandler` class
    * `BackchannelAuthenticationRequestHandlerSpi` interface
    * `BackchannelAuthenticationRequestHandlerSpiAdapter` class
    * `BaseBackchannelAuthenticationEndpoint` class

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.30 to 2.33.


2.12 (2018-10-10)
-----------------

- `AuthleteApiImpl` class
    * Implemented `getTokenList` methods.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.23 to 2.30.
    * Updated the version o `gson` from 2.6.2 to 2.8.5.


2.11 (2018-09-11)
-----------------

- `AuthleteApiImpl` class
    * Added `getJaxRsClientBuilder()` method.
    * Added `setJaxRsClientBuilder(ClientBuilder)` method.

- `pom.xml`
    * Updated the version of `javax.ws.rs-api` from 2.0 to 2.1.


2.10 (2018-07-21)
-----------------

- `authlete-java-common` library
    * Updated the version from 2.18 to 2.23.

- `AuthleteApiImpl` class
    * Implemented `registerClient(ClientRegistrationRequest)` method.
    * Implemented `verifyJose(JoseVerifyRequest)` method.


2.9 (2018-05-26)
----------------

- `HeaderClientCertificateExtractor` class
    * Updated the implementation of `extractClientCertificateChain()` method
      to ignore wrong `X-Ssl-Cert[-*]` headers sent from misconfigured Apache
      servers.


2.8 (2018-05-09)
----------------

- `BaseEndpoint` class
    * Slightly changed the behavior of `onError(WebApplicationException)`.
      The old implementation called `exception.printStackTrace()`, but the new
      implementation does nothing.
    * Added `extractClientCertificateChain(HttpServletRequest)` method.
    * Added `extractClientCertificate(HttpServletRequest)` method.

- `BaseResourceEndpoint` class
    * Added a variant of `validateAccessToken()` method which accepts
      `String clientCertificate` as the 5th parameter.

- `BaseTokenEndpoint` class
    * Added a variant of `handle()` method which accepts 5 arguments.

- `TokenRequestHandler` class
    * Added a variant of `handle()` method which accepts 3 arguments.

- New parts
    * `ClientCertificateExtractor` interface
    * `HeaderClientCertificateExtractor` class
    * `HttpsRequestClientCertificateExtractor` class

- Updated the version of authlete-java-common to 2.18 and updated
  `AuthleteApiImpl` accordingly.


2.7 (2017-12-08)
----------------

- Fixed a bug in `RevocationRequestHandler`. When the `action` response
  parameter in a response from `/api/auth/revocation` is `OK`,
  Content-Type of the response returned from the revocation endpoint to
  the client application should be `application/javascript` instead of
  `application/json`.


2.6 (2017-11-20)
----------------

- Added `JaxRsUtils` class.


2.5 (2017-11-16)
----------------

- Updated the version of authlete-java-common to 2.11.

- Implemented new `AuthleteApi` methods added by authlete-java-common-2.11.


2.4 (2017-10-18)
----------------

- Updated the version of authlete-java-common to 2.10.

- Supported `Settings.setReadTimeout(int)` method.


2.3 (2017-10-13)
----------------

- Updated the version of authlete-java-common to 2.9.

- Implemented `AuthleteApi.getSettings()` method.


2.2 (2017-07-21)
----------------

- Updated the version of authlete-java-common to 2.7.

- Implemented `AuthleteApi.standardIntrospection(StandardIntrospectionRequest)` method.

- Added `BaseIntrospectionEndpoint` class and `IntrospectionRequestHandler` class.


2.1 (2017-07-10)
----------------

- Fixed bug where user authentication time was being treated as milliseconds instead of seconds.


2.0 (2017-03-18)
----------------

- Updated the version of authlete-java-common to 2.1.

- Implemented the following new methods of `AuthleteApi` interface.
    * `deleteClientAuthorization(long, String)`
    * `getClientAuthorizationList(ClientAuthorizationGetListRequest)`
    * `updateClientAuthorization(long, ClientAuthorizationUpdateRequest)`


1.8 (2017-02-17)
----------------

- Updated the version of authlete-java-common to 1.40.

- Implemented `deleteGrantedScopes(long, String)` method of `AuthleteApi`
  interface.


1.7 (2017-02-15)
----------------

- Modified `AuthleteApiImpl` to catch `IllegalStateException` which
  `Response.hasEntity()` may throw.


1.6 (2017-02-14)
----------------

- Updated the version of authlete-java-common to 1.39.

- Implemented `getGrantedScopes(long, String)` method of `AuthleteApi`
  interface.


1.5 (2017-02-03)
----------------

- Changed `application/json` to `application/json;UTF-8` in `callPostApi()`
  defined in `AuthleteApiImpl`.


1.4 (2016-07-30)
----------------

- Added `getScopes()` method to `AuthorizationDecisionHandlerSpi` and
  `AuthorizationRequestHandlerSpi` to provide a function to replace scopes.

- Updated `AuthleteApiImpl` for `AuthleteApi` version 1.34.


1.3 (2016-04-25)
----------------

- Added `getProperties()` method to `AuthorizationDecisionHandlerSpi`,
  `AuthorizationRequestHandlerSpi` and `TokenRequestHandlerSpi` to
  support the mechanism to associate extra properties with access tokens.

- Added `getProperties()` method, `setProperties(Property[])` method,
  and other setter methods to `AccessTokenInfo` class.


1.2 (2016-02-08)
----------------

- Added some `Base*Endpoint` classes.

- Added classes to validate an access token.

- Added utility classes to implement a userinfo endpoint.


1.1 (2016-02-06)
----------------

- Added utility classes to implement (a) a JWK Set endpoint,
  (b) a configuration endpoint, and (c) a revocation endpoint.

- Updated `AuthleteApiImpl` for `AuthleteApi` version 1.28.


1.0 (2016-01-11)
----------------

- The first release.
