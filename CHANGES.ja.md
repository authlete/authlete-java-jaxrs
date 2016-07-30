変更点
======

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
