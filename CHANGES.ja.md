変更点
======

2.90 (2025-12-29)
-----------------

- `pom.xml`
    * authlete-java-common のバージョンを 4.27 から 4.33 へ更新。

- `AuthleteApiCaller` クラス
    * `callCredentialNonce(CredentialNonceRequest, Options)` メソッドを追加。

- 新しい型
    * `BaseCredentialNonceEndpoint` クラス
    * `CredentialNonceRequestHandler` クラス


2.89 (2025-11-04)
-----------------

- `pom.xml`
    * authlete-java-common のバージョンを 4.23 から 4.27 へ更新。
    * nimbus-jose-jwt のバージョンを 10.0.2 から 10.5 へ更新。

- `AuthleteApiImpl` クラス
    * `credentialNonce(CredentialNonceRequest, Options)` メソッドを実装。

- `AuthleteApiImplV3` クラス
    * `credentialNonce(CredentialNonceRequest, Options)` メソッドを実装。


2.88 (2025-10-07)
-----------------

- `pom.xml`
    * authlete-java-common のバージョンを 4.20 から 4.23 へ更新。
    * nimbus-jose-jwt のバージョンを 9.37.2 から 10.0.2 へ更新。

- `AuthleteApiJaxrsImpl` クラス
    * Authlete API 呼び出しから HTTP レスポンスヘッダーを抽出する機能を追加。
    * `callGetApi()` と `callPostApi()` メソッドがレスポンスヘッダーをキャプチャし、
      `setResponseHeaders()` メソッドを使用して `ApiResponse` オブジェクトに設定するように変更。
    * これにより、API レスポンスから `Request-Id` などのヘッダーへのアクセスが可能に。

2.87 (2025-05-03)
-----------------

- `AuthleteApiImpl` クラス
    * authlete-java-common のバージョン 4.20 で `AuthleteApi`
      インターフェースに追加された
      `nativeSsoLogout(NativeSsoLogoutRequest, Options)`
      メソッドのダミー実装を追加。 `/nativesso/logout` API は Authlete 2.x
      では利用できない。

- `AuthleteApiImplV3` クラス
    * authlete-java-common のバージョン 4.20 で `AuthleteApi`
      インターフェースに追加された
      `nativeSsoLogout(NativeSsoLogoutRequest, Options)` メソッドを実装。

- `pom.xml`
    * authlete-java-common のバージョンを 4.19 から 4.20 へ更新。


2.86 (2025-05-02)
-----------------

- `AuthleteApiCaller` クラス
    * `/auth/authorization/issue` API を呼ぶためのメソッド群に `sessionId`
      パラメータを追加。

- `AuthleteApiImpl` クラス
    * authlete-java-common のバージョン 4.18 で `AuthleteApi`
      インターフェースに追加された `nativeSso(NativeSsoRequest, Options)`
      メソッドのダミー実装を追加。 `/nativesso` API は Authlete 2.x
      では利用できない。

- `AuthleteApiImplV3` クラス
    * authlete-java-common のバージョン 4.18 で `AuthleteApi`
      インターフェースに追加された `nativeSso(NativeSsoRequest, Options)`
      メソッドを実装。

- `AuthorizationDecisionHandler` クラス
    * `/auth/authorization/issue` API の `sessionId`
      リクエストパラメータをサポート。

- `AuthorizationDecisionHandlerSpi` インターフェース
    * `getSessionId()` メソッドを追加。

- `AuthorizationDecisionHandlerSpiAdapter` クラス
    * `getSessionId()` メソッドの空実装を追加。

- `TokenRequestHandler` クラス
    * `TokenResponse.NATIVE_SSO` アクションをサポート。

- `TokenRequestHandlerSpi` インターフェース
    * 破壊的変更: `tokenExchange(TokenResponse)` メソッドのメソッドシグネチャを
      `tokenExchange(TokenResponse, Map<String, Object>)` へ変更。
    * 破壊的変更: `jwtBearer(TokenResponse)` メソッドのメソッドシグネチャを
      `jwtBearer(TokenResponse, Map<String, Object>)` へ変更。
    * `nativeSso(TokenResponse, Map<String, Object>)` メソッドを追加。

- `TokenRequestHandlerSpiAdapter` クラス
    * 破壊的変更: `tokenExchange(TokenResponse)` メソッドのメソッドシグネチャを
      `tokenExchange(TokenResponse, Map<String, Object>)` へ変更。
    * 破壊的変更: `jwtBearer(TokenResponse)` メソッドのメソッドシグネチャを
      `jwtBearer(TokenResponse, Map<String, Object>)` へ変更。
    * `nativeSso(TokenResponse, Map<String, Object>)` メソッドの空実装を追加。

- `pom.xml`
    * authlete-java-common のバージョンを 4.17 から 4.19 へ更新。


2.85 (2025-02-13)
-----------------

- `com.authlete.common` のバージョンを 4.16 から 4.17 更新。


2.84 (2025-01-24)
-----------------

- `TestRequest` オブジェクトを削除し、モックに置換。


2.82 (2025-01-12)
-----------------

- いくつかのリクエストハンドラークラス群、ベースエンドポイントクラス群、API 実装クラス群にリクエストオプションを追加。


2.81 (2024-10-20)
-----------------

- 新しい型
    * `RequestUrlResolver` クラス

- `pom.xml`
    * `com.authlete.http:http-field-parser:1.0` を追加。
    * 重複していた `org.apache.maven.plugins:maven-compiler-plugin` を削除。


2.81 (2024-10-20)
-----------------

- 新しい型
    * `RequestUrlResolver` クラス

- `pom.xml`
    * `com.authlete.http:http-field-parser:1.0` を追加。
    * 重複していた `org.apache.maven.plugins:maven-compiler-plugin` を削除。


2.80 (2024-10-02)
-----------------

- `AuthleteApiCaller` クラス
    * `callUserInfo(String, String, String, String, String)` メソッドを
      `callUserInfo(UserInfoRequestHandler.Params)` へ変更。

- `BaseEndpoint` クラス
    * `extractHeadersAsPairs(HttpServletRequest)` メソッドを追加。

- `UserInfoRequestHandler.Params` クラス
    * `getTargetUri()` メソッドを追加。
    * `setTargetUri(URI)` メソッドを追加。
    * `getHeaders()` メソッドを追加。
    * `setHeaders(Pair[])` メソッドを追加。
    * `isRequestBodyContained()` メソッドを追加。
    * `setRequestBodyContained(boolean)` メソッドを追加。
    * `isDpopNonceRequired()` メソッドを追加。
    * `setDpopNonceRequired(boolean)` メソッドを追加。


2.79 (2024-06-24)
-----------------

- `BackchannelAuthenticationRequestHandler` クラス
    * `handle(Params)` メソッドを追加。

- `BaseBackchannelAuthenticationEndpoint` クラス
    * `handle(AuthleteApi, BackchannelAuthenticationRequestHandlerSpi, Params)` メソッドを追加。

- `BaseDeviceAuthorizationEndpoint` クラス
    * `handle(AuthleteApi, Params)` メソッドを追加。

- `BaseRevocationEndpoint` クラス
    * `handle(AuthleteApi, Params)` メソッドを追加。

- `DeviceAuthorizationRequestHandler` クラス
    * `handle(Params)` メソッドを追加。

- `PushedAuthReqHandler.Params` クラス
    * `getClientAttestation()` メソッドを追加。
    * `setClientAttestation(String)` メソッドを追加。
    * `getClientAttestationPop()` メソッドを追加。
    * `setClientAttestationPop(String)` メソッドを追加。

- `RevocationRequestHandler` クラス
    * `handle(Params)` メソッドを追加。

- `TokenRequestHandler.Params` クラス
    * `getClientAttestation()` メソッドを追加。
    * `setClientAttestation(String)` メソッドを追加。
    * `getClientAttestationPop()` メソッドを追加。
    * `setClientAttestationPop(String)` メソッドを追加。

- 新しい型
    * `BackchannelAuthenticationRequestHandler.Params` クラス
    * `DeviceAuthorizationRequestHandler.Params` クラス
    * `HandlerUtility` クラス
    * `RevocationRequestHandler.Params` クラス


2.74 (2024-05-14)
-----------------

- `AuthleteApiImplV3` 実装
    * token create batch status API の path の修正。


2.73 (2024-05-14)
-----------------

- `AuthleteApiImplV3` 実装
    * いくつかの API path の修正。


2.72 (2024-05-14)
-----------------

- `AuthleteApiImplV3` 実装
    * `tokenCreateBatch(TokenCreateRequest[] request, boolean dryRun)` メソッドを実装。
    * `getTokenCreateBatchStatus(String requestId)` メソッドを実装。


2.71 (2024-05-07)
-----------------

- `AuthleteApi` 実装
    * `getTokenList()` メソッドを変更。
    * `getTokenList(String clientIdentifier, String subject)` メソッドを変更。
    * `getTokenList(int start, int end)` メソッドを変更。
    * `getTokenList(String clientIdentifier, String subject, int start, int end)` メソッドを変更。
    * `getTokenList(TokenStatus)` メソッドを実装。
    * `getTokenList(int start, int end, TokenStatus tokenStatus)` メソッドを実装。
    * `getTokenList(String clientIdentifier, String subject, TokenStatus tokenStatus)` メソッドを実装。
    * `getTokenList(String clientIdentifier, String subject, int start, int end, TokenStatus tokenStatus)` メソッドを実装。


2.70 (2023-12-17)
-----------------

- `BasePushedAuthReqEndpoint` クラス
    * `handle(AuthleteApi, Params)` メソッドを追加。


2.69 (2023-12-17)
-----------------

- `AuthleteApi` 実装
    * `authorizationTicketInfo(AuthorizationTicketInfoRequest)` メソッドを実装。
    * `authorizationTicketUpdate(AuthorizationTicketUpdateRequest)` メソッドを実装。

- `AuthleteApiCaller` クラス
    * `dpop`, `htm`, `htu` 引数を `callPushedAuthReq` メソッドに追加。

- `PushedAuthReqHandler` クラス
    * `handle(Params)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.82 から 3.88 へ更新。

- 新しい型
    * `PushedAuthReqHandler.Params` クラス


2.68 (2023-11-16)
-----------------

- `Authlete Java JAX-RS` と `Authlete Java Jakarta` プロジェクトを同期。


2.66 (2023 年 10 月 31 日)
--------------------------

- `AccessTokenValidator` クラス
    * `validate(IntrospectionRequest)` メソッドを追加。

- `AuthleteApiCaller` クラス
    * 引数 `headers` を `tokenFailResponse` メソッドに追加。
    * 引数 `headers` を `tokenIssue` メソッドに追加。
    * 引数 `headers` を `userInfoIssue` メソッドに追加。
    * `callIntrospection(IntrospectionRequest)` メソッドを追加。

- `BaseResourceEndpoint` クラス
    * `validateAccessToken(AuthleteApi, IntrospectionRequest)` メソッドを追加。

- `ResponseUtil` クラス
    * `ok(String, Map<String, Object>)` メソッドを追加。
    * `ok(String, MediaType, Map<String, Object>)` メソッドを追加。
    * `noContent(Map<String, Object>)` メソッドを追加。
    * `badRequest(String, Map<String, Object>)` メソッドを追加。
    * `unauthorized(String, String, Map<String, Object>)` メソッドを追加。
    * `forbidden(String, Map<String, Object>)` メソッドを追加。
    * `notFound(String, Map<String, Object>)` メソッドを追加。
    * `internalServerError(String, Map<String, Object>)` メソッドを追加。
    * `created(String, Map<String, Object>)` メソッドを追加。
    * `internalServerError(String, MediaType, Map<String, Object>)` メソッドを追加。
    * `bearerError(Status, String, Map<String, Object>)` メソッドを追加。
    * `tooLarge(String, Map<String, Object>)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.79 から 3.82 へ更新。


2.65 (2023 年 09 月 18 日)
--------------------------

- `AuthleteApi` 実装
    * `credentialJwtIssuerMetadata(CredentialJwtIssuerMetadataRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.77 から 3.79 へ更新。

- 新しい型
    * `BaseCredentialJwtIssuerMetadataEndpoint` クラス
    * `CredentialJwtIssuerMetadataRequestHandler` クラス


2.64 (2023 年 09 月 04 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `introspectionSignKeyId` を `callStandardIntrospection` メソッドの引数から削除.

- `IntrospectionRequestHandler` クラス
    * 内部クラス `Params` から `introspectionSignKeyId` プロパティを削除。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.76 から 3.77 へ更新。


2.63 (2023 年 09 月 03 日)
--------------------------

- `AuthleteApiCaller` クラス
    * [JWT Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response) を
    サポートするため、`callStandardIntrospection` メソッドを更新。

- `BaseIntrospectionEndpoint` クラス
    * `handle(AuthleteApi, Params)` メソッドを追加。

- `IntrospectionRequestHandler` クラス
    * 内部クラス `Params` を追加。
    * `JWT` アクションをサポートするため、`process` メソッドを更新。

- `ResponseUtil` クラス
    * `tokenIntrospection(String)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.75 から 3.76 へ更新。


2.62 (2023 年 08 月 02 日)
--------------------------

- `AuthleteApi` 実装
  - `credentialIssuerJwks(CredentialIssuerJwksRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.71 から 3.75 へ更新。


2.61 (2023 年 07 月 12 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `callCredentialOfferInfo` メソッドを追加。

- 新しい型
    * `BaseCredentialOfferUriEndpoint` クラス
    * `CredentialOfferUriRequestHandler` クラス


2.60 (2023 年 07 月 10 日)
--------------------------

- `AuthleteApi` 実装
  - `credentialBatchParse(CredentialBatchParseRequest)` メソッドを実装。
  - `credentialBatchIssue(CredentialBatchIssueRequest)` メソッドを実装。
  - `credentialDeferredParse(CredentialDeferredParseRequest)` メソッドを実装。
  - `credentialDeferredIssue(CredentialDeferredIssueRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.68 から 3.71 へ更新。


2.59 (2023 年 07 月 03 日)
--------------------------

- `AuthleteApi` 実装
  - `idTokenReissue(IDTokenReissueRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.67 から 3.68 へ更新。


2.58 (2023 年 06 月 28 日)
--------------------------

- `AuthleteApi` 実装
  - `credentialOfferCreate(CredentialOfferCreateRequest)` メソッドを実装。
  - `credentialOfferInfo(CredentialOfferInfoRequest)` メソッドを実装。
  - `credentialSingleParse(CredentialSingleParseRequest)` メソッドを実装。
  - `credentialSingleIssue(CredentialSingleIssueRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.56 から 3.67 へ更新。


2.57 (2023 年 04 月 13 日)
--------------------------

- `AuthleteApi` 実装
    * `credentialIssuerMetadata(CredentialIssuerMetadataRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.52 から 3.56 へ更新。

- 新しい型
    * `BaseCredentialIssuerMetadataEndpoint` クラス
    * `CredentialIssuerMetadataRequestHandler` クラス


2.56 (2023 年 03 月 03 日)
--------------------------

- `AuthorizationPageModel` クラス
    * `getClaimsForIdToken()` メソッドを追加。
    * `setClaimsForIdToken(String[])` メソッドを追加。
    * `getClaimsForUserInfo()` メソッドを追加。
    * `setClaimsForUserInfo(String[])` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.46 から 3.52 へ更新。
    * `gson` のバージョンを 2.8.9 から 2.10.1 へ更新。
    * `nimbus-jose-jwt` のバージョンを 9.22 から 9.31 へ更新。


2.55 (2022 年 12 月 31 日)
--------------------------

- `FederationRegistrationRequestHandler` クラス
    * 成功応答の Content-Type を `application/jose` から `application/entity-statement+jwt` に変更。
      OpenID Connect Federation 1.0 仕様のドラフト 25 では Content-Type は `application/jose`
      となっているが、将来のドラフトで修正される。


2.54 (2022 年 12 月 11 日)
--------------------------

- `AuthorizationPageModel` クラス
    * 動的スコープを認識するよう更新。


2.53 (2022 年 11 月 29 日)
--------------------------

- `ResponseUtil` クラス
    * `jose(String)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.45 から 3.46 へ更新。

- 新しい型
    * `BaseFederationRegistrationEndpoint` クラス
    * `FederationRegistrationRequestHandler` クラス


2.52 (2022 年 11 月 28 日)
--------------------------

- `AuthleteApi` 実装
    * `federationRegistration(FederationRegistrationRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.44 から 3.45 へ更新。


2.51 (2022 年 11 月 23 日)
--------------------------

- `BaseConfigurationEndpoint` クラス
    * `handle(AuthleteApi)` メソッドの実装をバージョン 2.49 のものへ戻す。

- `ConfigurationRequestHandler` クラス
    * `handle(boolean)` メソッドの実装をバージョン 2.49 のものへ戻す。


2.50 (2022 年 11 月 23 日)
--------------------------

- `AuthleteApi` 実装
    * `getServiceConfiguration(ServiceConfigurationRequest)` メソッドを実装。

- `BaseConfigurationEndpoint` クラス
    * `handle(AuthleteApi, ServiceConfigurationRequest)` メソッドを追加。

- `ConfigurationRequestHandler` クラス
    * `handle(ServiceConfigurationRequest)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.41 から 3.44 へ更新。


2.49 (2022 年 11 月 16 日)
--------------------------

- `AuthleteApi` 実装
    * `federationConfiguration(FederationConfigurationRequest)` メソッドを実装。
    * `gm(GMRequest)` メソッドの不具合を修正。
    * `updateClientLockFlag(String, boolean)` メソッドの不具合を修正。

- `ResponseUtil` クラス
    * `entityStatement(String)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.30 から 3.41 へ更新。

- 新しい型
    * `BaseFederationConfigurationEndpoint` クラス
    * `FederationConfigurationRequestHandler` クラス


2.48 (2022 年 08 月 10 日)
--------------------------

- `TokenRequestHandler` クラス
    * トークンリクエストが [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html)
      で定義されている認可種別 `urn:ietf:params:oauth:grant-type:jwt-bearer`
      を利用している場合に Authlete の `/auth/token` API から返却される
      `TokenResponse.Action.JWT_BEARER` をサポート。

- `TokenRequestHandlerSpi` インターフェース
    * [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) で定義されている認可種別
      `urn:ietf:params:oauth:grant-type:jwt-bearer` をサポートするため
      `jwtBearer(TokenResponse)` メソッドを追加。

- `TokenRequestHandlerSpiAdapter` クラス
    * `jwtBearer(TokenResponse)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.26 から 3.30 へ更新。


2.47 (2022 年 07 月 24 日)
--------------------------

- `TokenRequestHandler` クラス
    * トークンリクエストがトークン交換リクエスト
      ([RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html))
      である場合に Authlete の `/auth/token` API から返却される
      `TokenResponse.Action.TOKEN_EXCHANGE` をサポート。

- `TokenRequestHandlerSpi` インターフェース
    * [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
      をサポートするため `tokenExchange(TokenResponse)` メソッドを追加。

- `TokenRequestHandlerSpiAdapter` クラス
    * `tokenExchange(TokenResponse)` メソッドを実装。


2.46 (2022 年 07 月 23 日)
--------------------------

- `AuthleteApi` 実装
    * `tokenRevoke(TokenRevokeRequest)` メソッドを実装

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.23 から 3.26 へ更新。


2.45 (2022 年 06 月 18 日)
--------------------------

- `AuthleteApi` 実装
    * Authlete API バージョン 3 をサポート

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.18 から 3.23 へ更新。
    * `com.google.code.gson:gson` のバージョンを 2.8.6 から 2.8.9 へ更新。


2.44 (2022 年 06 月 09 日)
--------------------------

- `pom.xml`
    * PR #27 allow deployment to internal and external registries


2.43 (2022 年 04 月 30 日)
--------------------------

- `AuthleteApiCaller` クラス
    * 引数 `verifiedClaimsForTx` を `authorizationIssue` メソッドに追加。
    * 引数 `verifiedClaimsForTx` を `userInfoIssue` メソッドに追加。

- `AuthleteApiImpl` クラス
    * `updateClientLockFlag(String, boolean)` メソッドを実装。

- `AuthorizationDecisionHandler` クラス
    * `verified_claims/claims` 内の変換クレームをサポート。

- `AuthorizationDecisionHandler.Params` クラス
    * `getRequestedVerifiedClaimsForTx()` メソッドを追加。
    * `setRequestedVerifiedClaimsForTx(StringArray[])` メソッドを追加。

- `UserInfoRequestHandler` クラス
    * `verified_claims/claims` 内の変換クレームをサポート。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.9 から 3.18 へ更新。
    * `com.nimbusds:nimbus-jose-jwt` のバージョンを 8.14 から 9.22 へ更新。

- 新しい型
    * `VerifiedClaimsCollector` クラス


2.42 (2022 年 03 月 23 日)
--------------------------

- `AuthorizationDecisionHandler.Params` クラス
    * `isOldIdaFormatUsed()` メソッドを追加。
    * `setOldIdaFormatUsed(boolean)` メソッドを追加。

- `AuthorizationDecisionHandlerSpi` インターフェース
    * `getVerifiedClaims(String, Object)` メソッドを追加。
    * `getVerifiedClaims(String, VerifiedClaimsConstraint)` メソッドを非推奨化。

- `AuthorizationPageModel` クラス
    * `isOldIdaFormatUsed()` メソッドを追加。
    * `setOldIdaFormatUsed(boolean)` メソッドを追加。

- `UserInfoRequestHandler.Params` クラス
    * `isOldIdaFormatUsed()` メソッドを追加。
    * `setOldIdaFormatUsed(boolean)` メソッドを追加。

- `UserInfoRequestHandlerSpi` インターフェース
    * `getVerifiedClaims(String, Object)` メソッドを追加。
    * `getVerifiedClaims(String, VerifiedClaimsConstraint)` メソッドを非推奨化。


2.41 (2021 年 11 月 28 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `claimsForTx` パラメーターを `authorizationIssue()` に追加。
    * `claimsForTx` パラメーターを `userInfoIssue()` に追加。

- `AuthorizationDecisionHandler` クラス
    * `claimsForTx` を用意するよう更新。

- `AuthorizationDecisionHandler.Params` クラス
    * `getRequestedClaimsForTx()` メソッドを追加。
    * `setRequestedClaimsForTx(String[])` メソッドを追加。

- `UserInfoRequestHandler` クラス
    * `claimsForTx` を用意するよう更新。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.4 から 3.9 へ更新。


2.40 (2021 年 10 月 25 日)
--------------------------

- `HeaderClientCertificateXSslExtractor` クラス
    * [不具合修正] SSL_CLIENT_CERT_CHAIN_n (Apache Module mod_ssl) の n は 1 からではなく 0 から開始する。


2.39 (2021 年 10 月 21 日)
--------------------------

- `HeaderClientCertificateClientCertExtractor` クラス
    * `Client-Cert` ヘッダーが無い場合に対応。 (PR 24)


2.38 (2021 年 10 月 20 日)
--------------------------

- 新しいクラス
    * `BaseGrantManagementEndpoint`


2.37 (2021 年 10 月 20 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `gm(GMRequest)` メソッドを追加。

- `ClientRegistrationRequestHandler` クラス
    * `ClientRegistrationResponse.Action.UNAUTHORIZED` をサポート。

- `pom.xml`
    * `authlete-java-common` のバージョンを 3.0 から 3.4 へ更新。

- 新しいクラス
    * `GMRequestHandler`


2.36 (2021 年 08 月 25 日)
--------------------------

OpenJDK 8 で再ビルド。


2.35 (2021 年 08 月 25 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `echo(Map<String, String>)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.97 から 3.0 へ更新。


2.34 (2021 年 08 月 25 日)
--------------------------

- `HeaderClientCertificateExtractor` クラス
    * クラス定義に `abstract` を追加。
    * `X-Ssl` 及び `X-Ssl-Chain-*` を `HeaderClientCertificateXSslExtractor` へ移動。

- 新しいクラス
    * `HeaderClientCertificateClientCertExtractor`
    * `HeaderClientCertificateXSslExtractor`


2.33 (2021 年 07 月 09 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `hskCreate(HskCreateRequest)` メソッドを追加。
    * `hskDelete(String)` メソッドを追加。
    * `hskGet(String)` メソッドを追加。
    * `hskGetList()` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.82 から 2.97 へ更新。


2.32 (2021 年 06 月 20 日)
--------------------------

- 新しいクラス
    * `CertificateUtils`


2.31 (2020 年 11 月 02 日)
--------------------------

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.81 から 2.82 へ更新。


2.30 (2020 年 11 月 02 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `tokenDelete(String)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.73 から 2.81 へ更新。


2.29 (2020 年 06 月 29 日)
--------------------------

- `HeaderClientCertificateExtractor` クラス
    * Nginx の `$ssl_client_escaped_cert` をサポート。


2.28 (2020 年 04 月 09 日)
--------------------------

- `AuthleteApiImpl` クラス
    * DPoP サポートを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.71 から 2.73 へ更新。
    * `com.nimbusds:nimbus-jose-jwt:8.14` を追加。


2.27 (2020 年 03 月 07 日)
--------------------------

- `AccessTokenValidator` クラス
    * 内部クラス `Params` を追加。
    * `validate(Params)` メソッドを追加。

- `AuthleteApiCaller` クラス
    * `callIntrospection`, `callToken`, `callUserInfo` メソッドに
      引数 `dpop`, `htm`, `htu` を追加。

- `AuthorizationDecisionHandlerSpi` インターフェース
    * `getVerifiedClaims(String, VerifiedClaimsConstraint)` メソッドの戻り値の型を
      `VerifiedClaims` から `List<VerifiedClaims>` へ変更。

- `BaseResourceEndpoint` クラス
    * `validateAccessToken(AuthleteApi, Params)` メソッドを追加。

- `BaseTokenEndpoint` クラス
    * `handle(AuthleteApi, TokenRequestHandlerSpi, Params)` メソッドを追加。

- `BaseUserInfoEndpoint` クラス
    * `handle(AuthleteApi, UserInfoRequestHandlerSpi, Params)` メソッドを追加。

- `TokenRequestHandler` クラス
    * 内部クラス `Params` を追加。
    * `handle(Params)` メソッドを追加。

- `UserInfoRequestHandler` クラス
    * 内部クラス `Params` を追加。
    * `handle(Params)` メソッドを追加。

- `UserInfoRequestHandlerSpi` インターフェース
    * `getVerifiedClaims(String, VerifiedClaimsConstraint)` メソッドの戻り値の型を
      `VerifiedClaims` から `List<VerifiedClaims>` へ変更。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.65 から 2.71 へ更新。


2.26 (2019 年 12 月 23 日)
--------------------------

- `AuthorizationPageModel` クラス
    * `getVerifiedClaimsForIdToken()` メソッドを追加。
    * `setVerifiedClaimsForIdToken(Pair[])` メソッドを追加。
    * `getVerifiedClaimsForUserInfo()` メソッドを追加。
    * `setVerifiedClaimsForUserInfo(Pair[])` メソッドを追加。
    * `isAllVerifiedClaimsForIdTokenRequested()` メソッドを追加。
    * `setAllVerifiedClaimsForIdTokenRequested(boolean)` メソッドを追加。
    * `isAllVerifiedClaimsForUserInfoRequested()` メソッドを追加。
    * `setAllVerifiedClaimsForUserInfoRequested(boolean)` メソッドを追加。
    * `isIdentityAssuranceRequired()` メソッドを追加。
    * `setIdentityAssuranceRequired(boolean)` メソッドを追加。
    * `getPurposesForIdToken()` メソッドを追加。
    * `setPurposesForIdToken(Pair[])` メソッドを追加。
    * `getPurposesForUserInfo()` メソッドを追加。
    * `setPurposesForUserInfo(Pair[])` メソッドを追加。

- `BaseAuthorizationDecisionEndpoint` クラス
    * `handle(AuthleteApi, AuthorizationDecisionHandlerSpi, Params)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.64 から 2.65 へ更新。


2.25 (2019 年 12 月 23 日)
--------------------------

- `AuthorizationDecisionHandlerSpi` インターフェース
    * `getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)` メソッドを追加。

- `AuthorizationPageModel` クラス
    * `getPurpose()` メソッドを追加。
    * `setPurpose(String)` メソッドを追加。
    * `getPurposesForIdToken()` メソッドを追加。
    * `setPurposesForIdToken(Pair[])` メソッドを追加。
    * `getPurposesForUserInfo()` メソッドを追加。
    * `setPurposesForUserInfo(Pair[])` メソッドを追加。

- `UserInfoRequestHandlerSpi` インターフェース
    * `getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.61 から 2.64 へ更新。

- 新しいクラス
    * `AuthorizationDecisionHandler.Params`


2.24 (2019 年 12 月 15 日)
--------------------------

- `JaxRsUtils` クラス
    * `parseFormUrlencoded(String)` メソッドを追加。


2.23 (2019 年 12 月 05 日)
--------------------------

- `AuthorizationPageModel` クラス
    * `getAuthorizationDetails()` メソッドを追加。
    * `setAuthorizationDetails(String)` メソッドを追加。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.51 から 2.61 へ更新。


2.22 (2019 年 12 月 04 日)
--------------------------

- `AuthorizationDecisionHandlerSpi` インターフェース
    * `getSub()` メソッドを追加。

- `AuthorizationRequestHandlerSpi` インターフェース
    * `getSub()` メソッドを追加。


2.21 (2019 年 11 月 13 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `callPushedAuthReq` メソッド群を追加。

- `ResponseUtil` クラス
    * `toLarge(String)` メソッドを追加。

- 新しいクラス
    * `BasePushedAuthReqEndpoint`
    * `PushedAuthReqHandler`


2.20 (2019 年 10 月 05 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `deleteClient(String)` メソッドを実装。
    * `getClient(String)` メソッドを実装。
    * `pushAuthorizationRequest(PushedAuthReqRequest)` メソッドを実装。
    * `registerRequestObject(RequestObjectRequest)` メソッドを削除。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.50 から 2.51 へ更新。


2.19 (2019 年 08 月 24 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `registerRequestObject(RequestObjectRequest)` メソッドを実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.49 から 2.50 へ更新。


2.18 (2019 年 07 月 12 日)
--------------------------

- `AuthleteApiCaller` クラス
    * ID トークン生成のために、いくつかのパラメーターを `callDeviceComplete(String userCode, String subject, DeviceCompleteRequest.Result result, Property[] properties, String[] scopes, String errorDescription, URI errorUri)` メソッドの引数に追加。

- `BaseEndpoint` class
    * `takeAttribute(HttpSession session, String key)` メソッドを追加。

- 新しいクラス
    * `BaseDeviceAuthorizationEndpoint` クラス
    * `BaseDeviceCompleteEndpoint` クラス
    * `BaseDeviceVerificationEndpoint` クラス
    * `DeviceAuthorizationPageModel` クラス
    * `DeviceAuthorizationRequestHandler` クラス
    * `DeviceCompleteRequestHandler` クラス
    * `DeviceVerificationPageModel` クラス
    * `DeviceVerificationRequestHandler` クラス
    * `DeviceCompleteRequestHandlerSpi` クラス
    * `DeviceCompleteRequestHandlerSpiAdapter` クラス
    * `DeviceVerificationRequestHandlerSpi` クラス
    * `DeviceVerificationRequestHandlerSpiAdapter` クラス

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.41 から 2.49 へ更新。


2.17 (2019 年 05 月 30 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `callClientRegistration(String json)` メソッドを追加。
    * `callClientRegistration(String json, String initialAccessToken)` メソッドを追加。
    * `callClientRegistrationGet(String clientId, String registrationAccessToken)` メソッドを追加。
    * `callClientRegistrationUpdate(String clientId, String json, String registrationAccessToken)` メソッドを追加。
    * `callClientRegistrationDelete(String clientId, String registrationAccessToken)` メソッドを追加。

- `ResponseUtil` クラス
    * `created(String entity)` メソッドを追加。

- 新しいクラス
    * `BaseClientRegistrationEndpoint` クラス
    * `ClientRegistrationRequestHandler` クラス

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.36 から 2.41 へ更新。


2.16 (2019 年 03 月 05 日)
--------------------------

- `BackchannelAuthenticationRequestHandler` クラス
    * `BackchannelAuthenticationRequestHandlerSpi` インターフェースに対する変更に応じて、いくつかの箇所を修正。

- `BackchannelAuthenticationRequestHandlerSpi` インターフェース
    * `BackchannelAuthenticationIssueResponse` 型の引数を `startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes)` メソッドに追加。

- `BackchannelAuthenticationRequestHandlerAdapter` クラス
    * `BackchannelAuthenticationRequestHandlerSpi` インターフェースに対する変更に応じて、 `startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes)` メソッドを修正。


2.15 (2019 年 02 月 28 日)
--------------------------

- `AuthleteApiCaller` クラス
    * error description と error URI をサポートするよう、 `callBackchannelAuthenticationComplete(String, String, Result, long, String, Map<String, Object>, Property[], String[])` メソッドを変更。

- `BackchannelAuthenticationCompleteRequestHandler` クラス
    * error description と error URI をサポートするよう実装を変更。

- `BackchannelAuthenticationCompleteRequestHandlerSpi` インターフェース
    * `getErrorDescription()` メソッドを追加。
    * `getErrorUri()` メソッドを追加。

- `BackchannelAuthenticationCompleteRequestHandlerSpiAdapter` クラス
    * `getErrorDescription()` メソッドを実装。
    * `getErrorUri()` メソッドを実装。


2.14 (2019 年 01 月 17 日)
--------------------------

- `BackchannelAuthenticationRequestHandler` クラス
    * `binding_message` リクエストパラメーターの検証を行うよう、 `handleUserIdentification(BackchannelAuthenticationResponse)`
      メソッドの実装を変更。

- `BackchannelAuthenticationRequestHandlerSpi` インターフェース
    * `isValidBindingMessage(String)` メソッドを追加。

- `BackchannelAuthenticationRequestHandlerSpiAdapter` クラス
    * `isValidBindingMessage(String)` を実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.33 から 2.36 へ更新。


2.13 (2019 年 01 月 09 日)
--------------------------

- `AuthleteApiCaller` クラス
    * `callBackchannelAuthentication(MultivaluedMap<String, String>, String, String, String, String[] clientCertificatePath)` メソッドを追加。
    * `backchannelAuthenticationFail(String, BackchannelAuthenticationFailRequest.Reason)` メソッドを追加。
    * `callBackchannelAuthenticationIssue(String)` メソッドを追加。
    * `callBackchannelAuthenticationComplete(String, String, Result, long, String, Map<String, Object>, Property[], String[])` メソッドを追加。

- `AuthleteApiImpl` クラス
    * `backchannelAuthentication(BackchannelAuthenticationRequest)` を実装。
    * `backchannelAuthenticationIssue(BackchannelAuthenticationIssueRequest)` を実装。
    * `backchannelAuthenticationFail(BackchannelAuthenticationFailRequest)` を実装。
    * `backchannelAuthenticationComplete(BackchannelAuthenticationCompleteRequest)` を実装。

- 新しいクラスとインターフェース
    * `BackchannelAuthenticationCompleteRequestHandler` クラス
    * `BackchannelAuthenticationCompleteRequestHandlerSpi` インターフェース
    * `BackchannelAuthenticationCompleteRequestHandlerSpiAdapter` クラス
    * `BackchannelAuthenticationRequestHandler` クラス
    * `BackchannelAuthenticationRequestHandlerSpi` インターフェース
    * `BackchannelAuthenticationRequestHandlerSpiAdapter` クラス
    * `BaseBackchannelAuthenticationEndpoint` クラス

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.30 から 2.33 へ更新。


2.12 (2018 年 10 月 10 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `getTokenList` メソッド群を実装。

- `pom.xml`
    * `authlete-java-common` のバージョンを 2.23 から 2.30 へ更新。
    * `gson` のバージョンを 2.6.2 から 2.8.5 へ更新。


2.11 (2018 年 09 月 11 日)
--------------------------

- `AuthleteApiImpl` クラス
    * `getJaxRsClientBuilder()` メソッドを追加。
    * `setJaxRsClientBuilder(ClientBuilder)` メソッドを追加。

- `pom.xml`
    * `javax.ws.rs-api` のバージョンを 2.0 から 2.1 へ更新。


2.10 (2018 年 07 月 21 日)
--------------------------

- `authlete-java-common` ライブラリ
    * バージョン 2.18 から 2.23 へ更新

- `AuthleteApiImpl` クラス
    * `registerClient(ClientRegistrationRequest)` メソッドを実装。
    * `verifyJose(JoseVerifyRequest)` メソッドを実装。


2.9 (2018 年 05 月 26 日)
-------------------------

- `HeaderClientCertificateExtractor` クラス
    * 正しく設定されていない Apache サーバーから送られてくる誤った `X-SSl-Cert[-*]`
      ヘッダーを無視するよう、 `extractClientCertificateChain()` メソッドの実装を更新。


2.8 (2018 年 05 月 09 日)
-------------------------

- `BaseEndpoint` クラス
    * `onError(WebApplicationException)` メソッドの実装を若干変更。古い実装では
      `exception.printStackTrace()` を呼んでいたが、新しい実装は何もしない。
    * `extractClientCertificateChain(HttpServletRequest)` メソッドを追加。
    * `extractClientCertificate(HttpServletRequest)` メソッドを追加。

- `BaseResourceEndpoint` クラス
    * `String clientCertificate` を 5 番目の引数として取る `validateAccessToken()`
      メソッドのバリアントを追加。

- `BaseTokenEndpoint` クラス
    * 5 つの引数を取る `handle()` メソッドのバリアントを追加。

- `TokenRequestHandler` クラス
    * 3 つの引数を取る `handle()` メソッドのバリアントを追加。

- 新しい部品
    * `ClientCertificateExtractor` インターフェース
    * `HeaderClientCertificateExtractor` クラス
    * `HttpsRequestClientCertificateExtractor` クラス

- authlete-java-common のバージョンを 2.18 に更新し、 `AuthleteApiImpl`
　もそれに合わせて更新。


2.7 (2017 年 12 月 08 日)
-------------------------

- `RevocationRequestHandler` 内の不具合を修正。 `/api/auth/revocation` API
  からのレスポンスに含まれる `action` レスポンスパラメーターの値が `OK` の場合、
  リボケーションエンドポイントからクライアントアプリケーションに返すレスポンスの
  Content-Type は `application/json` ではなく `application/javascript`
  であるべき。


2.6 (2017 年 11 月 20 日)
-------------------------

- `JaxRsUtils` クラスを追加。


2.5 (2017 年 11 月 16 日)
-------------------------

- authlete-java-common のバージョンを 2.11 に更新。

- authlete-java-common-2.11 で追加された新しい `AuthleteApi` メソッド群を実装。


2.4 (2017 年 10 月 18 日)
-------------------------

- authlete-java-common のバージョンを 2.10 に更新。

- `Settings.setReadTimeout(int)` メソッドをサポート。


2.3 (2017 年 10 月 13 日)
-------------------------

- authlete-java-common のバージョンを 2.9 に更新。

- `AuthleteApi.getSettings()` メソッドを実装。


2.2 (2017 年 07 月 21 日)
-------------------------

- authlete-java-common のバージョンを 2.7 に更新。

- `AuthleteApi.standardIntrospection(StandardIntrospectionRequest)`
  メソッドを実装。

- `BaseIntrospectionEndpoint` クラスと `IntrospectionRequestHandler`
  クラスを追加。


2.1 (2017 年 07 月 10 日)
-------------------------

- ユーザー認証時刻を秒ではなくミリ秒で扱っていた不具合を修正。


2.0 (2017 年 03 月 18 日)
-------------------------

- authlete-java-common のバージョンを 2.1 に更新。

- `AuthleteApi` インターフェースの新しいメソッド群を実装。
    * `deleteClientAuthorization(long, String)`
    * `getClientAuthorizationList(ClientAuthorizationGetListRequest)`
    * `updateClientAuthorization(long, ClientAuthorizationUpdateRequest)`


1.8 (2017 年 02 月 17 日)
-------------------------

- authlete-java-common のバージョンを 1.40 に更新。

- `AuthleteApi` インターフェースの `deleteGrantedScopes(long, String)`
  メソッドを実装。


1.7 (2017 年 02 月 15 日)
-------------------------

- `Response.hasEntity()` が投げる可能性のある `IllegalStateException` を
  キャッチするように `AuthleteApiImpl` を修正。


1.6 (2017 年 02 月 14 日)
-------------------------

- authlete-java-common のバージョンを 1.39 に更新。

- `AuthleteApi` インターフェースの `getGrantedScopes(long, String)`
  メソッドを実装。


1.5 (2017 年 02 月 03 日)
-------------------------

- `AuthleteApiImpl` で定義されている `callPostApi()` メソッド内の
  `application/json` を `application/json;UTF-8` に変更。


1.4 (2016 年 07 月 30 日)
-------------------------

- `AuthorizationDecisionHandlerSpi`, `AuthorizationRequestHandlerSpi` に
  `getScopes()` メソッドを追加。スコープを置き換える機能を提供するため。

- `AuthleteApi` バージョン 1.34 に適合するように `AuthleteApiImpl` を更新。


1.3 (2016 年 04 月 25 日)
-------------------------

- アクセストークンにプロパティー群を関連づける仕組みをサポートするため、
  `AuthorizationDecisionHandlerSpi`, `AuthorizationRequestHandlerSpi`,
  `TokenRequestHandlerSpi` に `getProperties()` メソッドを追加。

- `AccessTokenInfo` クラスに、`getProperties()` メソッド、
  `setProperties(Property[])` メソッド、その他のセッターメソッド群を追加。


1.2 (2016 年 02 月 08 日)
-------------------------

- `Base*Endpoint` クラス群を追加。

- アクセストークンの有効性を調べるためのクラス群を追加。

- ユーザー情報エンドポイントを実装するためのユーティリティークラス群を追加。


1.1 (2016 年 02 月 06 日)
-------------------------

- (a) JWK Set エンドポイント、(b) 設定エンドポイント、
  (c) 取り消しエンドポイントを実装するためのユーティリティークラス群を追加。

- `AuthleteApi` バージョン 1.28 に適合するように `AuthleteApiImpl` を更新。


1.0 (2016 年 01 月 11 日)
-------------------------

- 最初のリリース
