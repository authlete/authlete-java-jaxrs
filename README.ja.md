JAX-RS (Java) 用 Authlete ライブラリ
====================================

概要
----

このライブラリは、[OAuth 2.0][1] および [OpenID Connect][2]
をサポートする認可サーバーと、
リソースサーバーを実装するためのユーティリティークラス群を提供します。

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

[java-oauth-server][3] はこのライブラリを使用している認可サーバーの実装で、
認可エンドポイントやトークンエンドポイントに加え、JWK Set エンドポイント、
設定エンドポイント、取り消しエンドポイントの実装を含んでいます。
また、[java-resource-server][19] はこのライブラリを使用しているリソースサーバーの実装です。
[OpenID Connect Core 1.0][13] で定義されている[ユーザー情報エンドポイント][20]
をサポートし、また、保護リソースエンドポイントの例を含んでいます。
あなたの認可サーバーおよびリソースサーバーの実装の開始点として、
これらのリファレンス実装を活用してください。


ライセンス
----------

  Apache License, Version 2.0


Maven
-----

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>authlete-java-jaxrs</artifactId>
    <version>2.25</version>
</dependency>
```


ソースコード
------------

  <code>https://github.com/authlete/authlete-java-jaxrs</code>


JavaDoc
-------

  <code>http://authlete.github.io/authlete-java-jaxrs</code>


説明
----

認可サーバーは次のエンドポイントを公開することが期待されています。

  1. 認可エンドポイント ([RFC 6749, 3.1.][9])
  2. トークンエンドポイント ([RFC 6749, 3.2][10])

このライブラリは、これらのエンドポイントを実装するためのユーティリティークラス群を提供します。
また、下記のエンドポイント用のユーティリティークラス群も含んでいます。

  3. JWK Set エンドポイント ([OpenID Connect Core 1.0][13])
  4. 設定エンドポイント ([OpenID Connect Discovery 1.0][12])
  5. 取り消しエンドポイント ([RFC 7009][14])
  6. ユーザー情報エンドポイント ([OpenID Connect Core 1.0][13])
  7. イントロスペクションエンドポイント ([RFC 7662][23])


### 認可エンドポイント

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
`generateAuthorizationPage()` です。 このメソッドは認可ページを生成するために呼ばれます。
このメソッドは、Authlete の `/api/auth/authorization` Web API からの応答を表す
`AuthorizationResponse` クラスのインスタンスを受け取ります。
そのインスタンスには、認可ページを生成するのに必要な情報が含まれています。

```java
Response generateAuthorizationPage(AuthorizationResponse info);
```

詳細は [JavaDoc][11] 及びリファレンス実装 ([java-oauth-server][3]) を参照してください。


### 認可決定エンドポイント

認可ページは、クライアントアプリケーションの名前や要求されている権限等の、認可リクエストに含まれる情報を表示します。
ユーザーはその情報を確認し、リクエストを認可するか拒否するかを決めます。
認可サーバーはその決定を受け取り、その決定に対応する応答を返します。
そのため、認可サーバーは、認可エンドポイントに加え、ユーザーによる決定を受け取るエンドポイントを用意しなければなりません。

`AuthorizationDecisionHandler` はその決定を処理するためのクラスです。
このクラスには、`AuthorizationRequestHandler` と同じように `handle()`
メソッドがあります。 また、このクラスのコンストラクターは、`AuthorizationRequestHandler`
のコンストラクターと同じように、`AuthorizationDecisionHandlerSpi`
インターフェースの実装を要求します。


### トークンエンドポイント

`TokenRequestHandler` はクライアントアプリケーションからのトークンリクエストを処理するためのクラスです。
このクラスには、`MultivaluedMap<String, String>` と `String` の二つの引数を取る
`handle()` メソッドがあります。 `MultivaluedMap` 引数はリクエストパラメーター群を表します。
一方の `String` 引数はトークンリクエストに含まれる `Authorization` ヘッダーの値です。

```java
public Response handle(
    MultivaluedMap<String, String> parameters, String authorization)
    throws WebApplicationException
```

トークンエンドポイントの実装は、トークンリクエストを処理する作業を
`handle()` メソッドに委譲することができます。

`TokenRequestHandler` のコンストラクターは、`AuthorizationRequestHandler`
のコンストラクターと同じように、`TokenRequestHandlerSpi` インターフェースの実装を要求します。

まとめると、トークンエンドポイント実装内のフローは次のようになります。

```java
// トークンリクエストのリクエストパラメーター群
MultivaluedMap<String, String> parameters = ...;

// Authorization ヘッダーの値
String authorization = ...;

// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// TokenRequestHandlerSpi インターフェースの実装。
TokenRequestHandlerSpi spi = ...;

// TokenRequestHandler クラスのインスタンスを生成する。
TokenRequestHandler handler = new TokenRequestHandler(api, spi);

// トークンリクエストを処理する作業をハンドラーに委譲する。
Response response = handler.handle(parameters, authorization);

// クライアントアプリケーションにレスポンスを返す。
return response;
```


### JWK Set エンドポイント

OpenID プロバイダーは、クライアントアプリケーションが (1) OpenID
プロバイダーの署名を検証できるように、また、(2) OpenID
プロバイダーへのリクエストを暗号化できるように、JSON Web Key Set
ドキュメント (JWK Set) を公開する必要があります。

`JwksRequestHandler` はそのようなエンドポイントへのリクエストを処理するためのクラスです。
このクラスは SPI 実装を要求しないので、使い方は簡単です。

```java
// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// JwksRequestHandler クラスのインスタンスを生成する。
JwksRequestHandler handler = new JwksRequestHandler(api);

// リクエストの処理をハンドラーに委譲する。
Response response = handler.handle();

// クライアントアプリケーションにレスポンスを返す。
return response;
```

さらに、`BaseJwksEndpoint` クラスはこの作業を信じられないほど簡単にします。
下記は、JWK Set エンドポイントの完全な実装例です。 `BaseJwksEndpoint` の
`handle()` メソッドは内部で `JwksRequestHandler` を使用しています。

```java
@Path("/api/jwks")
public class JwksEndpoint extends BaseJwksEndpoint
{
    @GET
    public Response get()
    {
        // JWK Set リクエストを処理する。
        return handle(AuthleteApiFactory.getDefaultApi());
    }
}
```


### 設定エンドポイント

[OpenID Connect Discovery 1.0][12] をサポートする OpenID プロバイダーは、自身の設定情報を
JSON フォーマットで返すエンドポイントを提供しなければなりません。フォーマットの詳細は
OpenID Connect Discovery 1.0 の [3. OpenID Provider Metadata][15] に記述されています。

`ConfigurationRequestHandler` はそのような設定エンドポイントへのリクエストを処理するためのクラスです。
このクラスは SPI 実装を要求しないので、使い方は簡単です。

```java
// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// ConfigurationRequestHandler クラスのインスタンスを作成する。
ConfigurationRequestHandler handler = new ConfigurationRequestHandler(api);

// リクエストの処理をハンドラーに委譲する。
Response response = handler.handle();

// クライアントアプリケーションにレスポンスを返す。
return response;
```

さらに、`BaseConfigurationEndpoint` クラスはこの作業を信じられないほど簡単にします。
下記は、設定エンドポイントの完全な実装例です。 `BaseConfigurationEndpoint` の
`handle()` メソッドは内部で `ConfigurationRequestHandler` を使用しています。

```java
@Path("/.well-known/openid-configuration")
public class ConfigurationEndpoint extends BaseConfigurationEndpoint
{
    @GET
    public Response get()
    {
        // 設定リクエストを処理する。
        return handle(AuthleteApiFactory.getDefaultApi());
    }
}
```

設定エンドポイントの URI は OpenID Connct Discovery 1.0 の
[4.1. OpenID Provider Configuration Request][16] で定義されていることに注意してください。
手短に言うと、URI は次の通りでなければなりません。

    発行者識別子 + /.well-known/openid-configuration

_発行者識別子_ は OpenID プロバイダーを識別するための URL です。
例えば `https://example.com` となります。
発行者識別子の詳細については、[3. OpenID Provider Meatadata][15]
(OpenID Connect Discovery 1.0) の `issuer`、および [2. ID Token][17]
(OpenID Connect Core 1.0) の `iss` を参照してください。


### 取り消しエンドポイント

認可サーバーは、アクセストークンやリフレッシュトークンを取り消すエンドポイントを公開してもよいです。
[RFC 7009][18] はそのような取り消しエンドポイントに関する仕様です。

`RevocationRequestHandler` は取り消しリクエストを処理するためのクラスです。
このクラスには、`MultivaluedMap<String, String>` と `String` の二つの引数を取る
`handle()` メソッドがあります。 `MultivaluedMap` 引数はリクエストパラメーター群を表します。
一方の `String` 引数は取り消しリクエストに含まれる `Authorization` ヘッダーの値です。

```java
public Response handle(
    MultivaluedMap<String, String> parameters, String authorization)
    throws WebApplicationException
```

取り消しエンドポイントの実装は、取り消しリクエストを処理する作業を
`handle()` メソッドに委譲することができます。

```java
// 取り消しリクエストのリクエストパラメーター群
MultivaluedMap<String, String> parameters = ...;

// Authorization ヘッダーの値
String authorization = ...;

// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// RevocationRequestHandler クラスのインスタンスを作成する。
RevocationRequestHandler handler = new RevocationRequestHandler(api);

// 取り消しリクエストの処理をハンドラーに委譲する。
Response response = handler.handle(parameters, authorization);

// クライアントアプリケーションにレスポンスを返す。
return response;
```

さらに、`BaseRevocationEndpoint` クラスはこの作業を信じられないほど簡単にします。
下記は、取り消しエンドポイントの完全な実装例です。 `BaseRevocationEndpoint` の
`handle()` メソッドは内部で `RevocationRequestHandler` を使用しています。

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
        // 取り消しリクエストを処理する。
        return handle(AuthleteApiFactory.getDefaultApi(), parameters, authorization);
    }
}
```


### ユーザー情報エンドポイント

ユーザー情報エンドポイントは、ユーザー情報を JSON または [JWT][21]
フォーマットで返す保護リソースエンドポイントです。 このエンドポイントの動作は
[OpenID Connect Core 1.0][13] の [5.3. UserInfo Endpoint][20] に記述されています。

`UserInfoRequestHandler` はユーザー情報リクエストを処理するためのクラスです。
このクラスには、アクセストークンを引数に取る `handle(String)` というメソッドがあります。
ユーザー情報エンドポイントの実装では、ユーザー情報リクエストの処理をこの `handle()`
メソッドに委譲することができます。

`UserInfoRequestHandler` クラスのコンストラクタは、実装固有の動作を制御するため、
`UseInfoRequestHandlerSpi` の実装を要求します。 この SPI クラスの主な目的は、
ユーザー情報エンドポイントからの応答に埋め込むクレーム値を集めることです。

次のコードは `UserInfoRequestHandler` の使い方を示すものです。

```java
// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// UserInfoRequestHandlerSpi インターフェースの実装。
UserInfoRequestHandlerSpi spi = ...;

// UserInfoRequestHandler クラスのインスタンスを作成する。
UserInfoRequestHandler handler = new UserInfoRequestHandler(api, spi);

// ユーザー情報リクエストに含まれているアクセストークン。
String accessToken = ...;

// ユーザー情報リクエストの処理をハンドラーに委譲する。
Response response = handler.handle(accessToken);

// クライアントアプリケーションにレスポンスを返す。
return response;
```

さらに、`BaseUserInfoEndpoint` クラスはこの作業を信じられないほど簡単にします。
下記は、ユーザー情報エンドポイントの実装例です。 `BaseUserInfoEndpoint` の
`handle()` メソッドは内部で `UserInfoRequestHandler` を使用しています。
ユーザー情報エンドポイントはアクセストークンを Bearer Token ([RFC 6750][22])
として受け取らなければならないことに注意してください。

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


### イントロスペクションエンドポイント

認可サーバーは、アクセストークンやリフレッシュトークンの情報を取得するエンドポイントを公開してもよいです。
そのようなエンドポイントはイントロスペクションエンドポイントと呼ばれ、[RFC 7662][23]
で標準仕様が定義されています。

`IntrospectionRequestHandler` はイントロスペクションリクエストを処理するためのクラスです。
このクラスには、`MultivaluedMap<String, String>` 型の引数を取る `handle()` メソッドがあります。
この引数はリクエストパラメーター群を表します。

```java
public Response handle(MultivaluedMap<String, String> parameters)
    throws WebApplicationException
```

イントロスペクションエンドポイントの実装は、イントロスペクションリクエストを処理する作業を
`handle()` メソッドに委譲することができます。

```java
// イントロスペクションリクエストのリクエストパラメーター群
MultivaluedMap<String, String> parameters = ...;

// AuthleteApi インターフェースの実装。
// 詳細は https://github.com/authlete/authlete-java-common を参照のこと。
AuthleteApi api = ...;

// IntrospectionRequestHandler クラスのインスタンスを作成する。
IntrospectionRequestHandler handler = new IntrospectionRequestHandler(api);

// イントロスペクションリクエストの処理をハンドラーに委譲する。
Response response = handler.handle(parameters);

// クライアントアプリケーションにレスポンスを返す。
return response;
```

さらに、`BaseIntrospectionEndpoint` クラスはこの作業を信じられないほど簡単にします。
下記は、イントロスペクションエンドポイントの実装例です。 `BaseIntrospectionEndpoint` の
`handle()` メソッドは内部で `IntrospectionRequestHandler` を使用しています。

```java
@Path("/api/introspection")
public class IntrospectionEndpoint extends BaseIntrospectionEndpoint
{
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response post(MultivaluedMap<String, String> parameters)
    {
        // RFC 7662 はイントロスペクションエンドポイントを保護することを
        // 要求しています。ですので、handle() メソッドを呼ぶ前に、API
        // 呼出し者が必要な権限を持っているか確認してください。

        // イントロスペクションリクエストを処理する。
        return handle(AuthleteApiFactory.getDefaultApi(), parameters);
    }
}
```

[RFC 7662][23] の [2.1. Introspection Request][24] には _"To prevent
token scanning attacks, the endpoint MUST also require some form of
authorization to access this endpoint"_
（トークンスキャン攻撃を防ぐため、エンドポイントへのアクセスには何らかの権限を要求しなければならない）
という記述があるので注意してください。このため、イントロスペクションエンドポイントの実際の実装では
`handle()` メソッドを呼ぶ前に API 呼出し者が必要な権限を持っていることを確認する必要があります。


注意
----

[authlete-java-common][4] のバージョン 2.9 で追加された `Settings` クラスの
`setConnectionTimeout(int)` メソッドを使うことで、接続タイムアウトを設定することができます。
しかし、(Java EE 8 の一部である) JAX-RS API 2.1
策定前は、接続タイムアウトを設定する方法が標準化されていないため、JAX-RS クライアント
API の実装によっては、`setConnectionTimeout(int)` による設定が反映されません。

本ライブラリの `setConnectionTimeout(int)` の[実装][25]は、[Jersey][26] 等、幾つかの
JAX-RS クライアント実装をサポートしています。
具体的なサポート状況については[ソースコード][25]を参照してください。

[authlete-java-common][4] のバージョン 2.10 で追加された `setReadTimeout(int)`
メソッドも `setConnectionTimeout(int)` メソッドと同じ問題を抱えています。


まとめ
------

このライブラリにより、OAuth 2.0 と OpenID Connect
をサポートする認可サーバー、およびリソースサーバーの実装作業が簡単になります。
詳細は [JavaDoc][11] 及びリファレンス実装 ([java-oauth-server][3] および
[java-resource-server][19]) を参照してください。


その他の情報
------------

- [Authlete][7] - Authlete ホームページ
- [java-oauth-server][3] - 認可サーバーの実装
- [java-resource-server][19] - リソースサーバーの実装
- [authlete-java-common][4] - Java 用 Authlete 共通ライブラリ


コンタクト
----------

| 目的 | メールアドレス       |
|:-----|:---------------------|
| 一般 | info@authlete.com    |
| 営業 | sales@authlete.com   |
| 広報 | pr@authlete.com      |
| 技術 | support@authlete.com |


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
[23]: http://tools.ietf.org/html/rfc7662
[24]: http://tools.ietf.org/html/rfc7662#section-2.1
[25]: https://github.com/authlete/authlete-java-jaxrs/blob/master/src/main/java/com/authlete/jaxrs/api/AuthleteApiImpl.java
[26]: https://jersey.github.io/
