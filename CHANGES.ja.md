変更点
======

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
