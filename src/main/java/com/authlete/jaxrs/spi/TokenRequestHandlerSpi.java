/*
 * Copyright (C) 2015-2025 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 */
package com.authlete.jaxrs.spi;


import java.util.Map;
import javax.ws.rs.core.Response;
import com.authlete.common.dto.Property;
import com.authlete.common.dto.TokenResponse;
import com.authlete.jaxrs.TokenRequestHandler;


/**
 * Service Provider Interface to work with {@link
 * com.authlete.jaxrs.TokenRequestHandler TokenRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.TokenRequestHandler TokenRequestHandler}
 * class.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public interface TokenRequestHandlerSpi
{
    /**
     * Authenticate an end-user.
     *
     * <p>
     * This method is called only when <a href=
     * "https://tools.ietf.org/html/rfc6749#section-4.3">Resource Owner
     * Password Credentials Grant</a> was used. Therefore, if you have
     * no mind to support Resource Owner Password Credentials, always
     * return {@code null}. In typical cases, you don't have to support
     * Resource Owner Password Credentials Grant.
     * FYI: RFC 6749 says <i>"The authorization server should take special
     * care when enabling this grant type and only allow it when other
     * flows are not viable."</i>
     * </p>
     *
     * <p>
     * Below is an example implementation using <a href=
     * "http://shiro.apache.org/">Apache Shiro</a>.
     * </p>
     *
     * <blockquote>
     * <pre style="border: 1px solid gray; padding: 0.5em; margin: 1em;">
     * <span style="color: gray;">&#x40;Override</span>
     * <span style="color: purple; font-weight: bold;">public</span> String authenticateUser(String username, String password)
     * {
     *     <span style="color: green;">// Pack the username and password into AuthenticationToken
     *     // which Apache Shiro's SecurityManager can accept.</span>
     *     <a href="https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authc/AuthenticationToken.html"
     *     style="text-decoration: none;">AuthenticationToken</a> credentials =
     *         <span style="color: purple; font-weight: bold;">new</span> <a href=
     *         "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authc/UsernamePasswordToken.html#UsernamePasswordToken(java.lang.String,%20java.lang.String)"
     *         style="text-decoration: none;">UsernamePasswordToken</a>(username, password);
     *
     *     <span style="color: purple; font-weight: bold;">try</span>
     *     {
     *         <span style="color: green;">// Authenticate the resource owner.</span>
     *         <a href="https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authz/AuthorizationInfo.html"
     *         style="text-decoration: none;">AuthenticationInfo</a> info =
     *             <a href="https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html"
     *             style="text-decoration: none;">SecurityUtils</a>.<a href=
     *             "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html#getSecurityManager()"
     *             style="text-decoration: none;">getSecurityManager()</a>.<a href=
     *             "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authc/Authenticator.html#authenticate(org.apache.shiro.authc.AuthenticationToken)"
     *             style="text-decoration: none;">authenticate</a>(credentials);
     *
     *         <span style="color: green;">// Get the subject of the authenticated user.</span>
     *         <span style="color: purple; font-weight: bold;">return</span> info.<a href=
     *         "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authc/AuthenticationInfo.html#getPrincipals()"
     *         style="text-decoration: none;">getPrincipals()</a>.<a href=
     *         "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/subject/PrincipalCollection.html#getPrimaryPrincipal()"
     *         style="text-decoration: none;">getPrimaryPrincipal()</a>.toString();
     *     }
     *     <span style="color: purple; font-weight: bold;">catch</span> (<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/authz/AuthorizationException.html"
     *     style="text-decoration: none;">AuthenticationException</a> e)
     *     {
     *         <span style="color: green;">// Not authenticated.</span>
     *         <span style="color: purple; font-weight: bold;">return</span> null;
     *     }
     * }</pre>
     * </blockquote>
     *
     * @param username
     *         The value of {@code username} parameter in the token request.
     *
     * @param password
     *         The value of {@code password} parameter in the token request.
     *
     * @return
     *         The subject (= unique identifier) of the authenticated
     *         end-user. If the pair of {@code username} and {@code
     *         password} is invalid, {@code null} should be returned.
     */
    String authenticateUser(String username, String password);


    /**
     * Get extra properties to associate with an access token.
     *
     * <p>
     * This method is expected to return an array of extra properties.
     * The following is an example that returns an array containing one
     * extra property.
     * </p>
     *
     * <pre style="border: 1px solid gray; padding: 0.5em; margin: 1em;">
     * <span style="color: gray;">&#x40;Override</span>
     * <span style="color: purple; font-weight: bold;">public</span> {@link Property}[] getProperties()
     * {
     *     <span style="color: purple; font-weight: bold;">return</span> <span style="color: purple; font-weight: bold;">new</span> {@link Property}[] {
     *         <span style="color: purple; font-weight: bold;">new</span> {@link Property#Property(String, String)
     *     Property}(<span style="color: darkred;">"example_parameter"</span>, <span style="color: darkred;">"example_value"</span>)
     *     };
     * }</pre>
     *
     * <p>
     * Extra properties returned from this method will appear as top-level entries
     * in a JSON response from an authorization server as shown in <a href=
     * "https://tools.ietf.org/html/rfc6749#section-5.1">5.1. Successful Response</a>
     * in RFC 6749.
     * </p>
     *
     * <p>
     * Keys listed below should not be used and they would be ignored on
     * the server side even if they were used. It's because they are reserved
     * in <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html"
     * >OpenID Connect Core 1.0</a>.
     * </p>
     *
     * <ul>
     *   <li>{@code access_token}
     *   <li>{@code token_type}
     *   <li>{@code expires_in}
     *   <li>{@code refresh_token}
     *   <li>{@code scope}
     *   <li>{@code error}
     *   <li>{@code error_description}
     *   <li>{@code error_uri}
     *   <li>{@code id_token}
     * </ul>
     *
     * <p>
     * Note that <b>there is an upper limit on the total size of extra properties</b>.
     * On the server side, the properties will be (1) converted to a multidimensional
     * string array, (2) converted to JSON, (3) encrypted by AES/CBC/PKCS5Padding, (4)
     * encoded by base64url, and then stored into the database. The length of the
     * resultant string must not exceed 65,535 in bytes. This is the upper limit, but
     * we think it is big enough.
     * </p>
     *
     * <p>
     * When the value of {@code grant_type} parameter contained in the token request
     * from the client application is {@code authorization_code} or {@code refresh_token},
     * extra properties are merged. Rules are as described in the table below.
     * </p>
     *
     * <blockquote>
     * <table border="1" cellpadding="5" style="border-collapse: collapse;">
     *   <thead>
     *     <tr>
     *       <th><code>grant_type</code></th>
     *       <th>Description</th>
     *     </tr>
     *   </thead>
     *   <tbody>
     *     <tr>
     *       <td><code>authorization_code</code></td>
     *       <td>
     *         <p>
     *           If the authorization code presented by the client application already
     *           has extra properties (this happens if {@link
     *           AuthorizationDecisionHandlerSpi#getProperties()} returned extra properties
     *           when the authorization code was issued), extra properties returned by this
     *           method will be merged into the existing extra properties. Note that the
     *           existing extra properties will be overwritten if extra properties returned
     *           by this method have the same keys.
     *         </p>
     *         <p>
     *           For example, if an authorization code has two extra properties, {@code a=1}
     *           and {@code b=2}, and if this method returns two extra properties, {@code a=A}
     *           and {@code c=3}, the resultant access token will have three extra properties,
     *           {@code a=A}, {@code b=2} and {@code c=3}.
     *         </p>
     *       </td>
     *     </tr>
     *     <tr>
     *       <td><code>refresh_token</code></td>
     *       <td>
     *         <p>
     *           If the access token associated with the refresh token presented by the
     *           client application already has extra properties, extra properties returned
     *           by this method will be merged into the existing extra properties. Note that
     *           the existing extra properties will be overwritten if extra properties
     *           returned by this method have the same keys.
     *         </p>
     *       </td>
     *   </tbody>
     * </table>
     * </blockquote>
     *
     * @return
     *         Extra properties. If {@code null} is returned, any extra
     *         property will not be associated.
     *
     * @since 1.3
     */
    Property[] getProperties();


    /**
     * Handle a token exchange request.
     *
     * <p>
     * This method is called when the grant type of the token request is
     * {@code "urn:ietf:params:oauth:grant-type:token-exchange"} (but see the
     * "NOTE 2" below). The grant type is defined in <a href=
     * "https://www.rfc-editor.org/rfc/rfc8693.html">RFC 8693: OAuth 2.0 Token
     * Exchange</a>.
     * </p>
     *
     * <p>
     * RFC 8693 is very flexible. In other words, the specification does not
     * define details that are necessary for secure token exchange. Therefore,
     * implementations have to complement the specification with their own
     * rules.
     * </p>
     *
     * <p>
     * The argument passed to this method is an instance of {@link TokenResponse}
     * that represents a response from Authlete's {@code /auth/token} API. The
     * instance contains information about the token exchange request such as
     * the value of the {@code subject_token} request parameter. Implementations
     * of this {@code tokenExchange} method are supposed to (1) validate the
     * information based on their own rules, (2) generate a token (e.g. an access
     * token) using the information, and (3) prepare a token response in the JSON
     * format that conforms to <a href=
     * "https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2">Section 2.2</a>
     * of RFC 8693.
     * </p>
     *
     * <p>
     * Authlete's {@code /auth/token} API performs validation of token exchange
     * requests to some extent. Therefore, authorization server implementations
     * don't have to repeat the same validation steps. See the <a href=
     * "https://authlete.github.io/authlete-java-common/">JavaDoc</a> of the
     * {@link TokenResponse} class for details about the validation steps.
     * </p>
     *
     * <p>
     * NOTE 1: Token Exchange is supported by Authlete 2.3 and newer versions.
     * If the Authlete server of your system is older than version 2.3, the grant
     * type ({@code "urn:ietf:params:oauth:grant-type:token-exchange"}) is not
     * supported and so this method is never called.
     * </p>
     *
     * <p>
     * NOTE 2: Even if the grant type is
     * {@code "urn:ietf:params:oauth:grant-type:token-exchange"}, if the service
     * is configured to support the "<a href=
     * "https://openid.net/specs/openid-connect-native-sso-1_0.html">OpenID
     * Connect Native SSO for Mobile Apps 1.0</a>" specification (a.k.a.
     * "Native SSO") and the token request complies with the specification,
     * the {@link #nativeSso(TokenResponse, Map) nativeSso} method is called
     * instead of this {@code tokenExchange} method. Native SSO is supported
     * in Authlete 3.0 and newer versions.
     * </p>
     *
     * @param tokenResponse
     *         A response from Authlete's {@code /auth/token} API.
     *
     * @param headers
     *         HTTP headers that should be included in the token response. For
     *         example, this map may include a key-value pair consisting of the
     *         {@code DPoP-Nonce} header and a DPoP nonce value (see <a href=
     *         "https://www.rfc-editor.org/rfc/rfc9449.html#section-8">RFC 9449:
     *         OAuth 2.0 Demonstrating Proof of Possession (DPoP), Section 8.
     *         Authorization Server-Provided Nonce</a>). This {@code headers}
     *         parameter was introduced in version 2.86 of authlete-java-jaxrs.
     *         This is a breaking change.
     *
     * @return
     *         A response from the token endpoint. It must conform to <a href=
     *         "https://www.rfc-editor.org/rfc/rfc8693.html#section-2.2">Section
     *         2.2</a> of RFC 8693. If this method returns {@code null},
     *         {@link TokenRequestHandler} will generate {@code 400 Bad Request}
     *         with <code>{"error":"unsupported_grant_type"}</code>.
     *
     * @since 2.47
     * @since Authlete 2.3
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc8693.html"
     *      >RFC 8693 OAuth 2.0 Token Exchange</a>
     */
    Response tokenExchange(TokenResponse tokenResponse, Map<String, Object> headers);


    /**
     * Handle a token request that uses the grant type
     * {@code "urn:ietf:params:oauth:grant-type:jwt-bearer"} (<a href=
     * "https://www.rfc-editor.org/rfc/rfc7523.html">RFC 7523</a>).
     *
     * <p>
     * This method is called when the grant type of the token request is
     * {@code "urn:ietf:params:oauth:grant-type:jwt-bearer"}. The grant type
     * is defined in <a href="https://www.rfc-editor.org/rfc/rfc7523.html"
     * >RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client
     * Authentication and Authorization Grants</a>.
     * </p>
     *
     * <p>
     * The grant type utilizes a JWT as an authorization grant, but the
     * specification does not define details about how the JWT is generated
     * by whom. As a result, it is not defined in the specification how to
     * obtain the key whereby to verify the signature of the JWT. Therefore,
     * each deployment has to define their own rules which are necessary to
     * determine the key for signature verification.
     * </p>
     *
     * <p>
     * The argument passed to this method is an instance of {@link TokenResponse}
     * that represents a response from Authlete's {@code /auth/token} API. The
     * instance contains information about the token request such as the value
     * of the {@code assertion} request parameter. Implementations of this
     * {@code jwtBearer} method are supposed to (1) validate the authorization
     * grant (= the JWT specified by the {@code assertion} request parameter),
     * (2) generate an access token, and (3) prepare a token response in the
     * JSON format that conforms to <a href=
     * "https://www.rfc-editor.org/rfc/rfc6749.html">RFC 6749</a>.
     * </p>
     *
     * <p>
     * Authlete's {@code /auth/token} API performs validation of token requests
     * to some extent. Therefore, authorization server implementations don't
     * have to repeat the same validation steps. Basically, what implementations
     * have to do is to verify the signature of the JWT. See the <a href=
     * "https://authlete.github.io/authlete-java-common/">JavaDoc</a> of the
     * {@link TokenResponse} class for details about the validation steps.
     * </p>
     *
     * <p>
     * NOTE: JWT Authorization Grant is supported by Authlete 2.3 and newer
     * versions. If the Authlete server of your system is older than version
     * 2.3, the grant type ({@code "urn:ietf:params:oauth:grant-type:jwt-bearer"})
     * is not supported and so this method is never called.
     * </p>
     *
     * @param tokenResponse
     *         A response from Authlete's {@code /auth/token} API.
     *
     * @param headers
     *         HTTP headers that should be included in the token response. For
     *         example, this map may include a key-value pair consisting of the
     *         {@code DPoP-Nonce} header and a DPoP nonce value (see <a href=
     *         "https://www.rfc-editor.org/rfc/rfc9449.html#section-8">RFC 9449:
     *         OAuth 2.0 Demonstrating Proof of Possession (DPoP), Section 8.
     *         Authorization Server-Provided Nonce</a>). This {@code headers}
     *         parameter was introduced in version 2.86 of authlete-java-jaxrs.
     *         This is a breaking change.
     *
     * @return
     *         A response from the token endpoint. It must conform to <a href=
     *         "https://www.rfc-editor.org/rfc/rfc6749.html">RFC 6749</a>. If
     *         this method returns {@code null}, {@link TokenRequestHandler}
     *         will generate {@code 400 Bad Request} with
     *         <code>{"error":"unsupported_grant_type"}</code>.
     *
     * @since 2.48
     * @since Authlete 2.3
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7521.html">RFC 7521
     *      Assertion Framework for OAuth 2.0 Client Authentication and
     *      Authorization Grants</a>
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7523.html">RFC 7523
     *      JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication
     *      and Authorization Grants</a>
     */
    Response jwtBearer(TokenResponse tokenResponse, Map<String, Object> headers);


    /**
     * Handle a token request that complies with the "<a href=
     * "https://openid.net/specs/openid-connect-native-sso-1_0.html">OpenID
     * Connect Native SSO for Mobile Apps 1&#x2E;0</a>" specification
     * (also known as "Native SSO").
     *
     * <p>
     * This method is called if the {@code action} parameter in the response
     * from Authlete's {@code /auth/token} API is {@link
     * com.authlete.common.dto.TokenResponse.Action#NATIVE_SSO NATIVE_SSO}.
     * This action value is returned when one of the following condition sets
     * is satisfied.
     * </p>
     *
     * <ol>
     * <li>Authorization Code Flow
     *   <ul>
     *   <li>The service's {@code nativeSsoSupported} property is set to
     *       {@code true}.
     *   <li>The service supports the {@code openid} and {@code device_sso} scopes.
     *   <li>The client is allowed to request the {@code openid} and
     *       {@code device_sso} scopes.
     *   <li>The grant type of the token request is {@code authorization_code}.
     *   <li>The authorization request preceding the token request included the
     *       {@code openid} and {@code device_sso} scopes.
     *   </ul>
     * <li>Refresh Token Flow
     *   <ul>
     *   <li>The service's {@code nativeSsoSupported} property is set to
     *       {@code true}.
     *   <li>The service supports the {@code device_sso} scope.
     *   <li>The client is allowed to request the {@code device_sso} scope.
     *   <li>The grant type of the token request is {@code refresh_token}.
     *   <li>The access token issued by the refresh token request still covers the
     *       {@code device_sso} scope, even if the scope coverage might have been
     *       narrowed.
     *   <li>The presented refresh token is associated with a user's authentication
     *       session. (In practice, only refresh tokens generated through the
     *       authorization code flow compliant with Native SSO can be used.)
     *   </ul>
     * <li>Token Exchange Flow
     *   <ul>
     *   <li>The service's {@code nativeSsoSupported} property is set to
     *       {@code true}.
     *   <li>The grant type of the token request is
     *       {@code urn:ietf:params:oauth:grant-type:token-exchange}.
     *   <li>The value of the {@code actor_token_type} request parameter is
     *       {@code urn:openid:params:token-type:device-secret}.
     *   </ul>
     * </ol>
     *
     * <h4>Session ID</h4>
     * <p>
     * When the {@code action} value is {@code NATIVE_SSO}, the response from the
     * {@code /auth/token} API contains a {@code sessionId} parameter. Its value
     * represents a user's authentication session - that is, a session ID.
     * </p>
     *
     * <p>
     * The authorization server must check whether the session ID is still valid.
     * Note that the session ID is not a value generated by Authlete but one that
     * was passed from the authorization server to the
     * {@code /auth/authorization/issue} API. Therefore, Authlete does not and
     * cannot determine whether the session ID is still valid.
     * </p>
     *
     * <p>
     * If the session ID is no longer valid, the authorization server should return
     * an error response from the token endpoint with the error code
     * {@code invalid_grant}.
     * </p>
     *
     * <h4>Device Secret</h4>
     *
     * <h5>Case 1: Device Secret in Authorization Code and Refresh Token Flows</h5>
     * <p>
     * When the grant type is {@code authorization_code} or {@code refresh_token},
     * the response from the {@code /auth/token} API may contain a
     * {@code deviceSecret} parameter. Its value represents a device secret passed
     * from the client application as the value of the {@code device_secret} request
     * parameter to the token endpoint. This request parameter is optional.
     * </p>
     *
     * <p>
     * When the {@code deviceSecret} parameter in the response from the
     * {@code /auth/token} API is not null, the authorization server must check
     * whether the device secret is valid. If the device secret is valid, the value
     * should be passed to the {@code /nativesso} API later without modification,
     * unless the authorization server chooses to reissue a new device secret.
     * </p>
     *
     * <p>
     * On the other hand, if the {@code deviceSecret} parameter is absent or its
     * value is invalid, the authorization server must generate a new device
     * secret. The new value should then be passed to the {@code /nativesso} API.
     * </p>
     *
     * <p>
     * Note that Authlete neither generates nor manages device secrets. It is the
     * authorization server's responsibility to do so. Therefore, Authlete does
     * not and cannot determine whether a device secret is valid.
     * </p>
     *
     * <h5>Case 2: Device Secret in Token Exchange Flow</h5>
     * <p>
     * When the grant type is
     * {@code urn:ietf:params:oauth:grant-type:token-exchange}, the response from
     * the {@code /auth/token} API contains {@code deviceSecret} and
     * {@code deviceSecretHash} parameters.
     * </p>
     *
     * <p>
     * The {@code deviceSecret} parameter represents the device secret presented
     * by the client application to the token endpoint as the value of the
     * {@code actor_token} request parameter.
     * </p>
     *
     * <p>
     * The {@code deviceSecretHash} parameter represents the device secret hash
     * embedded as the value of the {@code ds_hash} claim in the ID token that
     * the client application passed to the token endpoint as the value of the
     * {@code subject_token} request parameter.
     * </p>
     *
     * <p>
     * The authorization server must verify the binding between the device secret
     * and device secret hash. If the binding fails verification, the authorization
     * server should return an error response from the token endpoint with the
     * error code {@code invalid_grant}.
     * </p>
     *
     * <p>
     * Note that the Native SSO specification does not define how to compute a
     * device secret hash value from a device secret. The specification states,
     * <i>"The exact binding between the <code>ds_hash</code> and
     * <code>device_secret</code> is not specified by this profile."</i> Therefore,
     * the authorization server must define a rule regarding for computing the
     * device hash value and verify the binding based on that rule. A simple
     * example of hash computation logic is to compute the SHA-256 hash of a
     * device secret and base64url-encode the hash.
     * </p>
     *
     * <h5><code>/nativesso</code> API Call</h5>
     * <p>
     * After validating the session ID, device secret, and device secret hash as
     * necessary, the authorization server must call the {@code /nativesso} API
     * to generate a Native SSO-compliant ID token and token response. The API
     * expects the following request parameters.
     * </p>
     *
     * <table border="1" cellpadding="5" style="border-collapse: collapse;">
     *   <tr>
     *     <th>Parameter</th>
     *     <th>Description</th>
     *   <tr/>
     *   <tr>
     *     <td><code>accessToken</code></td>
     *     <td>
     *       <p>
     *       REQUIRED. If the response from the {@code /auth/token} API contains
     *       the {@code jwtAccessToken} parameter, its value must be used as the
     *       value of this {@code accessToken} request parameter to the
     *       {@code /nativesso} API. If the {@code jwtAccessToken} parameter is
     *       absent, the value of the {@code accessToken} parameter in the response
     *       from the {@code /auth/token} API should be used instead.
     *       </p>
     *       <p>
     *       The specified value is used as the value of the {@code access_token}
     *       property in the token response.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>refreshToken</code></td>
     *     <td>
     *       <p>
     *       OPTIONAL. If the {@code refreshToken} parameter is present in the
     *       response from the {@code /auth/token} API, its value should be
     *       specified as the value of this {@code refreshToken} request parameter
     *       to the {@code /nativesso} API. Note that whether a refresh token is
     *       issued depends on configuration.
     *       </p>
     *       <p>
     *       The specified value is used as the value of the {@code refresh_token}
     *       property in the token response.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>deviceSecret</code></td>
     *     <td>
     *       <p>
     *       REQUIRED. If the response from the {@code /auth/token} API contains
     *       the {@code deviceSecret} parameter, its value should be used as the
     *       value of this {@code deviceSecret} request parameter to the
     *       {@code /nativesso} API. The authorization server may choose to issue
     *       a new device secret; in that case, it is free to generate a new device
     *       secret and specify the new value.
     *       </p>
     *       <p>
     *       If the response from the {@code /auth/token} API does not contain the
     *       {@code deviceSecret} parameter, or if its value is invalid, the
     *       authorization server must generate a new device secret and specify it
     *       in the {@code deviceSecret} parameter to the {@code /nativesso} API.
     *       </p>
     *       <p>
     *       The specified value is used as the value of the {@code device_secret}
     *       property in the token response.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>deviceSecretHash</code></td>
     *     <td>
     *       <p>
     *       RECOMMENDED. The authorization server should compute the hash value
     *       of the device secret based on its own logic and specify the computed
     *       hash as the value of this {@code deviceSecretHash} request parameter
     *       to the {@code /nativesso} API.
     *       </p>
     *       <p>
     *       When the {@code deviceSecretHash} parameter is omitted, the
     *       implementation of the {@code /nativesso} API generates the device
     *       secret hash by computing the SHA-256 hash of the device secret and
     *       encoding it with base64url. Note that this hash computation logic is
     *       not a rule defined in the Native SSO specification; rather, it is
     *       Authlete-specific fallback logic used when the {@code deviceSecretHash}
     *       parameter is omitted.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>sub</code></td>
     *     <td>
     *       <p>
     *       OPTIONAL. The value of the {@code sub} claim to be embedded in the ID
     *       token. If omitted, the subject associated with the access token is
     *       used as the value of the {@code sub} claim.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>claims</code></td>
     *     <td>
     *       <p>
     *       OPTIONAL. Additional claims to be embedded in the ID token. The format
     *       of this parameter must be a JSON object.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>idtHeaderParams</code></td>
     *     <td>
     *       <p>
     *       OPTIONAL. Additional parameters to be embedded in the JWS header of
     *       the ID token. The format of this parameter must be a JSON object.
     *       </p>
     *     </td>
     *   </tr>
     *   <tr>
     *     <td><code>idTokenAudType</code></td>
     *     <td>
     *       <p>
     *       OPTIONAL. This parameter specifies the type of the {@code aud} claim
     *       in the ID token. If {@code "array"} is specified, the {@code aud}
     *       claim will be a JSON array. If {@code "string"} is specified, it will
     *       be a JSON string. If omitted, the {@code aud} claim will default to a
     *       JSON array.
     *       </p>
     *     </td>
     *   </tr>
     * </table>
     *
     * <p>
     * On success, the {@code action} parameter in the response from the
     * {@code /nativesso} API is {@code OK}. In this case, the value of the
     * {@code responseContent} parameter in the response can be used as the message
     * body of the token response from the token endpoint. The token endpoint
     * implementation can construct the token response as follows:
     * </p>
     *
     * <pre style="border: solid 1px black; padding: 0.5em;">
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     * Cache-Control: no-cache, no-store
     *
     * (Embed the value of the responseContent parameter in the response
     *  from the /nativesso API here)
     * </pre>
     *
     * <p>
     * The resulting message body will look like this:
     * </p>
     *
     * <pre style="border: solid 1px black; padding: 0.5em;">
     * {
     *   "access_token":      "(Access Token)",
     *   "token_type":        "(Token Type)",
     *   "expires_in":         (Lifetime in Seconds),
     *   "scope":             "(Space-separated Scopes)",
     *   "refresh_token":     "(Refresh Token)",
     *   "id_token":          "(ID Token)",
     *   "device_secret":     "(Device Secret)",
     *   "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
     * }</pre>
     *
     * @param tokenResponse
     *         A response from Authlete's {@code /auth/token} API.
     *
     * @param headers
     *         HTTP headers that should be included in the token response. For
     *         example, this map may include a key-value pair consisting of the
     *         {@code DPoP-Nonce} header and a DPoP nonce value (see <a href=
     *         "https://www.rfc-editor.org/rfc/rfc9449.html#section-8">RFC 9449:
     *         OAuth 2.0 Demonstrating Proof of Possession (DPoP), Section 8.
     *         Authorization Server-Provided Nonce</a>).
     *
     * @return
     *         A response from the token endpoint. It must conform to the
     *         "<a href="https://openid.net/specs/openid-connect-native-sso-1_0.html"
     *         >OpenID Connect Native SSO for Mobile Apps 1.0</a>" specification.
     *
     * @since 2.86
     * @since Authlete 3.0
     *
     * @see <a href="https://openid.net/specs/openid-connect-native-sso-1_0.html"
     *      >OpenID Connect Native SSO for Mobile Apps 1.0</a>
     */
    Response nativeSso(TokenResponse tokenResponse, Map<String, Object> headers);
}
