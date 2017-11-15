変更点
======

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
