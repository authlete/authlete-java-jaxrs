JAX-RS (Java) 用 Authlete ライブラリ
====================================

概要
----

このライブラリは、[OAuth 2.0][1] および [OpenID Connect][2]
をサポートする認可サーバーを実装するためのユーティリティークラス群を提供します。

このライブラリは、JAX-RS 2.0 API と [authlete-java-common][4]
ライブラリを用いて書かれています。 JAX-RS は _The Java API for RESTful Web
Services_ です。 JAX-RS 2.0 API は [JSR 339][5] で標準化され、Java EE 7
に含まれています。 一方、authlete-java-common は Authlete
が提供するもう一つのオープンソースライブラリで、[Authlete Web API][6]
とやりとりするためのクラス群を含んでいます。

[Authlete][7] は OAuth 2.0 と OpenID Connect の実装を提供するクラウドサービスです
([overview][8])。 認可データ (アクセストークン等)
や認可サーバー自体の設定、クライアントアプリケーション群の設定はクラウド上の
Authlete サーバーに保存されるため、Authlete
を使うことで「DB レス」の認可サーバーを構築することができます。

[java-oauth-server][3] はこのライブラリを使用している認可サーバーの実装です。
あなたの認可サーバーの実装の開始点として、このリファレンス実装を活用してください。


ライセンス
----------

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


ソースコード
------------

  https://github.com/authlete/authlete-java-jaxrs


JavaDoc
-------

  http://authlete.github.io/authlete-java-jaxrs


説明
----

認可サーバーは[認可エンドポイント][9]と[トークンエンドポイント][10]を公開することになります。
このライブラリは、これらのエンドポイントを実装するためのユーティリティークラス群を提供します。


#### 認可エンドポイント

`AuthorizationRequestHandler` はクライアントアプリケーションからの認可リクエストを処理するためのクラスです。
このクラスには、認可リクエストのリクエストパラメーター群を表す `MultivaluedMap<String, String>`
インスタンスを引数として取る `handle()` というメソッドがあります。

```java
public Response handle(MultivaluedMap<String, String> parameters)
    throws WebApplicationException
```

認可エンドポイントの実装は、認可リクエストを処理するという作業をこの
`handle()` メソッドに委譲することができます。

JAX-RS を使用しているのであれば、リクエストパラメーター群を含む
`MultivaluedMap<String, String>` インスタンスを取得して `handle()`
メソッドを呼ぶことは簡単な作業です。 しかし、ポイントは他の場所にあります。
`AuthorizationRequestHandlerSpi` インターフェースの実装を用意して
`AuthorizationRequestHandler` のコンストラクタに渡す必要があるのです。

`AuthorizationRequestHandlerSpi` は、`AuthorizationRequestHandler` の
`handle()` メソッドの動作を制御するための「サービス提供者インターフェース
(Service Provider Interface)」で、あなたが実装することになります。

まとめると、認可エンドポイント実装内のフローは次のようになります。

```java
// 認可リクエストのリクエストパラメーター群
MultivaluedMap<String, String> parameters = ...;

// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// AuthorizationRequestHandlerSpi インターフェースの実装。
AuthorizationRequestHandlerSpi spi = ...;

// AuthoriationRequestHandler クラスのインスタンスを作成する。
AuthorizationRequestHandler handler =
    new AuthorizationRequestHandler(api, spi);

// 認可リクエストを処理する作業をハンドラーに委譲する。
Response response = handler.handle(parameters);

// クライアントアプリケーションにレスポンスを返す。
return response;
```

`AuthorizationRequestHandlerSpi` に定義されているメソッド群のうち、最も重要なメソッドは
`generateAuthorizationPage()` です。 このメソッドは認可ページを生成するための呼ばれます。
このメソッドは、Authlete の `/api/auth/authorization` Web API からの応答を表す
`AuthorizationResponse` クラスのインスタンスを受け取ります。
そのインスタンスには、認可ページを生成するのに必要な情報が含まれています。

```java
Response generateAuthorizationPage(AuthorizationResponse info);
```

詳細は [JavaDoc][11] 及びリファレンス実装 ([java-oauth-server][3]) を参照してください。


#### 認可決定エンドポイント

認可ページは、クライアントアプリケーションの名前や要求されている権限等の、認可リクエストに含まれる情報を表示します。
ユーザーはその情報を確認し、リクエストを認可するか拒否するかを決めます。
認可サーバーはその決定を受け取り、その決定に対応する応答を返します。
そのため、認可サーバーは、認可エンドポイントに加え、ユーザーによる決定を受け取るエンドポイントを用意しなければなりません。

`AuthorizationDecisionHandler` はその決定を処理するためのクラスです。
このクラスには、`AuthorizationRequestHandler` と同じように `handle()`
メソッドがあります。 また、このクラスのコンストラクターは、`AuthorizationRequestHandler`
のコンストラクターと同じように、`AuthorizationDecisionHandlerSpi`
インターフェースの実装を要求します。


#### トークンエンドポイント

`TokenRequestHandler` はクライアントアプリケーションからのトークンリクエストを処理するためのクラスです。
このクラスには、`MultivaluedMap<String, String>` と `String` の二つの引数を取る
`handle()` メソッドがあります。 `MultivaluedMap` 引数はリクエストパラメーター群を表し、`String`
引数はトークンリクエストに含まれる `Authorization` ヘッダーの値です。

```java
public Response handle(
    MultivaluedMap<String, String> parameters, String authorization)
    throws WebApplicationException
```

トークンエンドポイントの実装は、トークンリクエストを処理する作業を
`handle()` メソッドに委譲することができます。

`TokenRequestHandler` のコンストラクターは、`AuthorizationRequestHandler`
のコンストラクターと同じように、`TokenRequestHandlerSpi` インターフェースの実装を取ります。

まとめると、トークンエンドポイント実装内のフローは次のようになります。

```java
// トークンリクエストのリクエストパラメーター群
MultivaluedMap<String, String> parameters = ...;

// Authorization ヘッダーの値
String authorization = ...;

// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// TokenRequestHandlerSpi インターフェースの実装
TokenRequestHandlerSpi spi = ...;

// TokenRequestHandler クラスのインスタンスを生成する。
TokenRequestHandler handler = new TokenRequestHandler(api, spi);

// トークンリクエストを処理する作業をハンドラーに委譲する。
Response response = handler.handle(parameters, authorization);

// クライアントアプリケーションにレスポンスを返す。
return response;
```


まとめ
------

このライブラリにより、OAuth 2.0 と OpenID Connect をサポートする認可サーバーの実装作業が簡単になります。
詳細は [JavaDoc][11] 及びリファレンス実装 ([java-oauth-server][3]) を参照してください。


その他の情報
------------

- [Authlete][7] - Authlete ホームページ
- [java-oauth-server][3] - 認可サーバーの実装
- [authlete-java-common][4] - Java 用 Authlete 共通ライブラリ


サポート
--------

[Authlete, Inc.](https://www.authlete.com/)<br/>
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
