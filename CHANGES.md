CHANGES
=======

2.52 (2022-11-28)
-----------------

- `AuthleteApi` implementations
    * Implemented the `federationRegistration(FederationRegistrationRequest)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.44 to 3.45.


2.51 (2022-11-23)
-----------------

- `BaseConfigurationEndpoint` class
    * Reverted the implementation of the `handle(AuthleteApi)` method back to
      that of the version 2.49.

- `ConfigurationRequestHandler` class
    * Reverted the implementation of the `handle(boolean)` method back to
      that of the version 2.49.


2.50 (2022-11-23)
-----------------

- `AuthleteApi` implementations
    * Implemented the `getServiceConfiguration(ServiceConfigurationRequest)` method.

- `BaseConfigurationEndpoint` class
    * Added `handle(AuthleteApi, ServiceConfigurationRequest)` method.

- `ConfigurationRequestHandler` class
    * Added `handle(ServiceConfigurationRequest)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.41 to 3.44.


2.49 (2022-11-16)
-----------------

- `AuthleteApi` implementations
    * Implemented the `federationConfiguration(FederationConfigurationRequest)` method.
    * Fixed a bug of the `gm(GMRequest)` method.
    * Fixed a bug of the `updateClientLockFlag(String, boolean)` method.

- `ResponseUtil` class
    * Added `entityStatement(String)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.30 to 3.41.

- New types
    * `BaseFederationConfigurationEndpoint` class
    * `FederationConfigurationRequestHandler` class


2.48 (2022-08-10)
-----------------

- `TokenRequestHandler` class
    * Supported `TokenResponse.Action.JWT_BEARER` which is returned from
      Authlete's `/auth/token` API when the token request uses the grant
      type `urn:ietf:params:oauth:grant-type:jwt-bearer` which is defined
      in [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html).

- `TokenRequestHandlerSpi` interface
    * Added `jwtBearer(TokenResponse)` method to support the grant type
      `urn:ietf:params:oauth:grant-type:jwt-bearer` which is defined in
      [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html).

- `TokenRequestHandlerSpiAdapter` class
    * Implemented `jwtBearer(TokenResponse)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.26 to 3.30.


2.47 (2022-07-24)
-----------------

- `TokenRequestHandler` class
    * Supported `TokenResponse.Action.TOKEN_EXCHANGE` which is returned from
      Authlete's `/auth/token` API when the token request is a token exchange
      request ([RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)).

- `TokenRequestHandlerSpi` interface
    * Added `tokenExchange(TokenResponse)` method to support
      [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html).

- `TokenRequestHandlerSpiAdapter` class
    * Implemented `tokenExchange(TokenResponse)` method.


2.46 (2022-07-23)
-----------------

- `AuthleteApi` implementations
    * Implemented the `tokenRevoke(TokenRevokeRequest)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.23 to 3.26.


2.45 (2022-06-18)
-----------------

- `AuthleteApi` implementations
    * Support Authlete API version 3

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.18 to 3.23.
    * Updated the version of `com.google.code.gson:gson` from 2.8.6 to 2.8.9.


2.44 (2022-06-09)
-----------------

- `pom.xml`
    * PR #27 allow deployment to internal and external registries


2.43 (2022-04-30)
-----------------

- `AuthleteApiCaller` class
    * Added an argument `verifiedClaimsForTx` to `authorizationIssue` method.
    * Added an argument `verifiedClaimsForTx` to `userInfoIssue` method.

- `AuthleteApiImpl` class
    * Implemented `updateClientLockFlag(String, boolean)` method.

- `AuthorizationDecisionHandler` class
    * Updated to support transformed claims in `verified_claims/claims`.

- `AuthorizationDecisionHandler.Params` class
    * Added `getRequestedVerifiedClaimsForTx()` method.
    * Added `setRequestedVerifiedClaimsForTx(StringArray[])` method.

- `UserInfoRequestHandler` class
    * Updated to support transformed claims in `verified_claims/claims`.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.9 to 3.18.
    * Updated the version of `com.nimbusds:nimbus-jose-jwt` from 8.14 to 9.22.

- New types
    * `VerifiedClaimsCollector` class


2.42 (2022-03-23)
-----------------

- `AuthorizationDecisionHandler.Params` class
    * Added `isOldIdaFormatUsed()` method.
    * Added `setOldIdaFormatUsed(boolean)` method.

- `AuthorizationDecisionHandlerSpi` interface
    * Added `getVerifiedClaims(String, Object)` method.
    * Marked `getVerifiedClaims(String, VerifiedClaimsConstraint)` method as deprecated.

- `AuthorizationPageModel` class
    * Added `isOldIdaFormatUsed()` method.
    * Added `setOldIdaFormatUsed(boolean)` method.

- `UserInfoRequestHandler.Params` class
    * Added `isOldIdaFormatUsed()` method.
    * Added `setOldIdaFormatUsed(boolean)` method.

- `UserInfoRequestHandlerSpi` interface
    * Added `getVerifiedClaims(String, Object)` method.
    * Marked `getVerifiedClaims(String, VerifiedClaimsConstraint)` method as deprecated.


2.41 (2021-11-28)
-----------------

- `AuthleteApiCaller` class
    * Added `claimsForTx` parameter to `authorizationIssue()`.
    * Added `claimsForTx` parameter to `userInfoIssue()`.

- `AuthorizationDecisionHandler` class
    * Updated to prepare `claimsForTx`.

- `AuthorizationDecisionHandler.Params` class
    * Added `getRequestedClaimsForTx()` method.
    * Added `setRequestedClaimsForTx(String[])` method.

- `UserInfoRequestHandler` class
    * Updated to prepare `claimsForTx`.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.4 to 3.9.


2.40 (2021-10-25)
-----------------

- `HeaderClientCertificateXSslExtractor` class
    * [bugfix] 'n' in SSL_CLIENT_CERT_CHAIN_n (Apache Module mod_ssl) starts from 0, not 1.


2.39 (2021-10-21)
-----------------

- `HeaderClientCertificateClientCertExtractor` class
    * Supported the case where the `Client-Cert` header is missing. (PR 24)


2.38 (2021-10-20)
-----------------

- New classes
    * `BaseGrantManagementEndpoint`


2.37 (2021-10-20)
-----------------

- `AuthleteApiImpl` class
    * Added `gm(GMRequest)` method.

- `ClientRegistrationRequestHandler` class
    * Supported `ClientRegistrationResponse.Action.UNAUTHORIZED`.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 3.0 to 3.4.

- New classes
    * `GMRequestHandler`


2.36 (2021-08-25)
-----------------

Rebuild with OpenJDK 8.


2.35 (2021-08-25)
-----------------

- `AuthleteApiImpl` class
    * Added `echo(Map<String, String>)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.97 to 3.0.


2.34 (2021-08-25)
-----------------

- `HeaderClientCertificateExtractor` class
    * Added `abstract` to the class definition.
    * Moved `X-Ssl` and `X-Ssl-Chain-*` to `HeaderClientCertificateXSslExtractor`.

- New classes
    * `HeaderClientCertificateClientCertExtractor`
    * `HeaderClientCertificateXSslExtractor`


2.33 (2021-07-09)
-----------------

- `AuthleteApiImpl` class
    * Added `hskCreate(HskCreateRequest)` method.
    * Added `hskDelete(String)` method.
    * Added `hskGet(String)` method.
    * Added `hskGetList()` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.82 to 2.97.


2.32 (2021-06-20)
-----------------

- New classes
    * `CertificateUtils`


2.31 (2020-11-02)
-----------------

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.81 to 2.82.


2.30 (2020-11-02)
-----------------

- `AuthleteApiImpl` class
    * Added `tokenDelete(String)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.73 to 2.81.


2.29 (2020-06-29)
-----------------

- `HeaderClientCertificateExtractor` class
    * Supported `$ssl_client_escaped_cert` of Nginx.


2.28 (2020-04-09)
-----------------

- `AuthleteApiImpl` class
    * Added DPoP support.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.71 to 2.73.
    * Added `com.nimbusds:nimbus-jose-jwt:8.14`.


2.27 (2020-03-07)
-----------------

- `AccessTokenValidator` class
    * Added `Params` inner class.
    * Added `validate(Params)` method.

- `AuthleteApiCaller` class
    * Added `dpop`, `htm` and `htu` arguments to `callIntrospection`,
     `callToken` and `callUserInfo` methods.

- `AuthorizationDecisionHandlerSpi` interface
    * Changed the return type of `getVerifiedClaims(String, VerifiedClaimsConstraint)`
      method from `VerifiedClaims` to `List<VerifiedClaims>`.

- `BaseResourceEndpoint` class
    * Added `validateAccessToken(AuthleteApi, Params)` method.

- `BaseTokenEndpoint` class
    * Added `handle(AuthleteApi, TokenRequestHandlerSpi, Params)` method.

- `BaseUserInfoEndpoint` class
    * Added `handle(AuthleteApi, UserInfoRequestHandlerSpi, Params)` method.

- `TokenRequestHandler` class
    * Added `Params` inner class.
    * Added `handle(Params)` method.

- `UserInfoRequestHandler` class
    * Added `Params` inner class.
    * Added `handle(Params)` method.

- `UserInfoRequestHandlerSpi` interface
    * Changed the return type of `getVerifiedClaims(String, VerifiedClaimsConstraint)`
      method from `VerifiedClaims` to `List<VerifiedClaims>`.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.65 to 2.71.


2.26 (2019-12-23)
-----------------

- `AuthorizationPageModel` class
    * Added `getVerifiedClaimsForIdToken()` method.
    * Added `setVerifiedClaimsForIdToken(Pair[])` method.
    * Added `getVerifiedClaimsForUserInfo()` method.
    * Added `setVerifiedClaimsForUserInfo(Pair[])` method.
    * Added `isAllVerifiedClaimsForIdTokenRequested()` method.
    * Added `setAllVerifiedClaimsForIdTokenRequested(boolean)` method.
    * Added `isAllVerifiedClaimsForUserInfoRequested()` method.
    * Added `setAllVerifiedClaimsForUserInfoRequested(boolean)` method.
    * Added `isIdentityAssuranceRequired()` method.
    * Added `setIdentityAssuranceRequired(boolean)` method.
    * Removed `getPurposesForIdToken()` method.
    * Removed `setPurposesForIdToken(Pair[])` method.
    * Removed `getPurposesForUserInfo()` method.
    * Removed `setPurposesForUserInfo(Pair[])` method.

- `BaseAuthorizationDecisionEndpoint` class
    * Added `handle(AuthleteApi, AuthorizationDecisionHandlerSpi, Params)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.64 to 2.65.


2.25 (2019-12-23)
-----------------

- `AuthorizationDecisionHandlerSpi` interface
    * Added `getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)` method.

- `AuthorizationPageModel` class
    * Added `getPurpose()` method.
    * Added `setPurpose(String)` method.
    * Added `getPurposesForIdToken()` method.
    * Added `setPurposesForIdToken(Pair[])` method.
    * Added `getPurposesForUserInfo()` method.
    * Added `setPurposesForUserInfo(Pair[])` method.

- `UserInfoRequestHandlerSpi` interface
    * Added `getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)` method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.61 to 2.64.

- New classes
    * `AuthorizationDecisionHandler.Params`


2.24 (2019-12-15)
-----------------

- `JaxRsUtils` class
    * Added `parseFormUrlencoded(String)` method.


2.23 (2019-12-05)
-----------------

- `AuthorizationPageModel` class
    * Added `getAuthorizationDetails()` method.
    * Added `setAuthorizationDetails(String)` method.

- `pom.xml`
    * Updated the version of `authlete-java-comon` from 2.51 to 2.61.


2.22 (2019-12-04)
-----------------

- `AuthorizationDecisionHandlerSpi` interface
    * Added `getSub()` method.

- `AuthorizationRequestHandlerSpi` interface
    * Added `getSub()` method.


2.21 (2019-11-13)
-----------------

- `AuthleteApiCaller` class
    * Added `callPushedAuthReq` methods.

- `ResponseUtil` class
    * Added `toLarge(String)` method.

- New classes
    * `BasePushedAuthReqEndpoint`
    * `PushedAuthReqHandler`


2.20 (2019-10-05)
-----------------

- `AuthleteApiImpl` class
    * Implemented `deleteClient(String)` method.
    * Implemented `getClient(String)` method.
    * Implemented `pushAuthorizationRequest(PushedAuthReqRequest)` method.
    * Removed `registerRequestObject(RequestObjectRequest) method.

- `pom.xml`
    * Updated the version of `authlete-java-common` from 2.50 to 2.51.


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
