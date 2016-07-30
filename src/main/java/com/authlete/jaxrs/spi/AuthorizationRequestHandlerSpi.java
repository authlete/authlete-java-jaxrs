/*
 * Copyright (C) 2015-2016 Authlete, Inc.
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


import javax.ws.rs.core.Response;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Property;


/**
 * Service Provider Interface to work with {@link
 * com.authlete.jaxrs.AuthorizationRequestHandler AuthorizationRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.AuthorizationRequestHandler
 * AuthorizationRequestHandler} class.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public interface AuthorizationRequestHandlerSpi
{
    /**
     * Check whether an end-user has already logged in or not.
     *
     * <p>
     * This method is called only when an authorization request comes
     * with {@code prompt=none}. Therefore, if you have no mind to
     * support {@code prompt=none}, always return {@code false}. See
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
     * >3.1.2.1. Authentication Request</a> in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a> for details about {@code prompt=none}.
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
     * <span style="color: purple; font-weight: bold;">public boolean</span> isUserAuthenticated()
     * {
     *     <span style="color: purple; font-weight: bold;">return</span> <a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html"
     *     style="text-decoration: none;">SecurityUtils</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html#getSubject()"
     *     style="text-decoration: none;">getSubject()</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/subject/Subject.html#isAuthenticated()"
     *     style="text-decoration: none;">isAuthenticated()</a>;
     * }</pre>
     * </blockquote>
     *
     * @return
     *         {@code true} if an end-user has already logged in. Otherwise,
     *         {@code false}. When {@code false} is returned, the client
     *         application will receive {@code error=login_required}.
     */
    boolean isUserAuthenticated();


    /**
     * Get the time when the current end-user was authenticated in
     * milliseconds since Unix epoch (1970-01-01).
     *
     * <p>
     * The value is used to check whether the elapsed time since the last
     * authentication has exceeded the maximum authentication age or not.
     * See {@code max_age} in "<a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
     * >3.1.2.1. Authentication Request</a>" in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a>, and {@code default_max_age} in "<a href=
     * "http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata"
     * >2. Client Metadata</a>" in <a href=
     * "http://openid.net/specs/openid-connect-registration-1_0.html"
     * >OpenID Connect Dynamic Client Registration 1.0</a> for details.
     * </p>
     *
     * <p>
     * This method is called only when an authorization request comes
     * with {@code prompt=none}. Therefore, if you have no mind to
     * support {@code prompt=none}, always return 0. See
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
     * >3.1.2.1. Authentication Request</a> in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a> for details about {@code prompt=none}.
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
     * <span style="color: purple; font-weight: bold;">public long</span> getUserAuthenticatedAt()
     * {
     *     <a href="https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/session/Session.html"
     *     style="text-decoration: none;">Session</a> session = <a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html"
     *     style="text-decoration: none;">SecurityUtils</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html#getSubject()"
     *     style="text-decoration: none;">getSubject()</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/subject/Subject.html#getSession(boolean)"
     *     style="text-decoration: none;">getSession</a>(false);
     *
     *     <span style="color: purple; font-weight: bold;">if</span> (session == <span style="color: purple; font-weight: bold;">null</span>)
     *     {
     *         <span style="color: purple; font-weight: bold;">return</span> 0;
     *     }
     *
     *     <span style="color: purple; font-weight: bold;">return</span> session.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/session/Session.html#getStartTimestamp()"
     *     style="text-decoration: none;">getStartTimestamp()</a>.getTime();
     * }</pre>
     * </blockquote>
     *
     * @return
     *         The time when the end-user was authenticated in milliseconds
     *         since Unix epoch (1970-01-01).
     */
    long getUserAuthenticatedAt();


    /**
     * Get the subject (= unique identifier) of the current end-user.
     * It must consist of only ASCII letters and its length must not
     * exceed 100.
     *
     * <p>
     * This method is called only when an authorization request comes
     * with {@code prompt=none}. Therefore, if you have no mind to
     * support {@code prompt=none}, always return {@code null}. See
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
     * >3.1.2.1. Authentication Request</a> in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a> for details about {@code prompt=none}.
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
     * <span style="color: purple; font-weight: bold;">public long</span> getUserAuthenticatedAt()
     * {
     *     <span style="color: purple; font-weight: bold;">return</span> (String)<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html"
     *     style="text-decoration: none;">SecurityUtils</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/SecurityUtils.html#getSubject()"
     *     style="text-decoration: none;">getSubject()</a>.<a href=
     *     "https://shiro.apache.org/static/1.2.3/apidocs/org/apache/shiro/subject/Subject.html#getPrincipal()"
     *     style="text-decoration: none;">getPrincipal()</a>;
     * }</pre>
     * </blockquote>
     *
     * @return
     *         The subject (= unique identifier) of the current end-user.
     */
    String getUserSubject();


    /**
     * Get the authentication context class reference (ACR) that was
     * satisfied when the current end-user was authenticated.
     *
     * <p>
     * The value returned by this method has an important meaning only
     * when an authorization requests {@code acr} claim as an essential
     * claim. Practically speaking, it is unlikely to happen. See "<a
     * href="http://openid.net/specs/openid-connect-core-1_0.html#acrSemantics"
     * >5.5.1.1. Requesting the "acr" Claim</a>" in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a> if you are interested in the details.
     * </p>
     *
     * <p>
     * This method is called only when an authorization request comes
     * with {@code prompt=none}. Therefore, if you have no mind to
     * support {@code prompt=none}, always return {@code null}. See
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
     * >3.1.2.1. Authentication Request</a> in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a> for details about {@code prompt=none}.
     * </p>
     *
     * <p>
     * If you don't know what ACR is, return {@code null}.
     * </p>
     *
     * @return
     *         The authentication context class reference (ACR) that
     *         was satisfied when the current end-user was authenticated.
     */
    String getAcr();


    /**
     * Generate an authorization page (HTML) to ask an end-user whether to
     * accept or deny an authorization request by a client application.
     *
     * <p>
     * Key information that should be displayed in an authorization page is
     * stored in the {@code info} object. For example, the name of the client
     * application can be obtained by calling {@code info.}{@link
     * AuthorizationResponse#getClient() getClient()}{@code .}{@link
     * com.authlete.common.dto.Client#getClientName() getClientName()} method.
     * Likewise, requested scopes can be obtained as an array of {@link
     * com.authlete.common.dto.Scope Scope} objects by calling {@code
     * info.}{@link AuthorizationResponse#getScopes() getScopes()} method.
     * </p>
     *
     * <p>
     * In an authorization page, an end-user will finally decide either to
     * grant authorization to the client application or to reject the
     * authorization request. The authorization server should receive the
     * decision and call {@link
     * com.authlete.jaxrs.AuthorizationDecisionHandler#handle(String,
     * String[], String[]) handle()} method.
     * </p>
     *
     * @param info
     *         A response from Authlete's {@code /api/auth/authorization} API.
     *         Key information that should be displayed in an authorization
     *         page is stored in the object.
     *
     * @return
     *         A response to show an authorization page.
     */
    Response generateAuthorizationPage(AuthorizationResponse info);


    /**
     * Get extra properties to associate with an access token and/or an
     * authorization code.
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
     * </blockquote>
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
     * This method is called only when an authorization request comes with {@code
     * prompt=none}. Therefore, if you have no mind to support {@code prompt=none},
     * always return {@code null}. See <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">3.1.2.1.
     * Authentication Request</a> in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core
     * 1.0</a> for details about {@code prompt=none}.
     * </p>
     *
     * @return
     *         Extra properties. If {@code null} is returned, any extra property will
     *         not be associated.
     *
     * @since 1.3
     */
    Property[] getProperties();


    /**
     * Get scopes to associate with an access token and/or an authorization code.
     *
     * <p>
     * If {@code null} is returned, the scopes specified in the original
     * authorization request from the client application are used. In other
     * cases, including the case of an empty array, the specified scopes will
     * replace the original scopes contained in the original authorization
     * request.
     * </p>
     *
     * <p>
     * Even scopes that are not included in the original authorization request
     * can be specified. However, as an exception, <code>"openid"</code> scope
     * is ignored on the server side if it is not included in the original
     * request. It is because the existence of <code>"openid"</code> scope
     * considerably changes the validation steps and because adding
     * <code>"openid"</code> triggers generation of an ID token (although the
     * client application has not requested it) and the behavior is a major
     * violation against the specification.
     * </p>
     *
     * <p>
     * If you add <code>"offline_access"</code> scope although it is not
     * included in the original request, keep in mind that the specification
     * requires explicit consent from the user for the scope (<a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess"
     * >OpenID Connect Core 1.0, 11. Offline Access</a>). When
     * <code>"offline_access"</code> is included in the original request, the
     * current implementation of Authlete's /api/auth/authorization API checks
     * whether the request has come along with <code>prompt</code> request
     * parameter and the value includes <code>"consent"</code>. However, note
     * that the implementation of Authlete's /api/auth/authorization/issue API
     * does not perform such checking if <code>"offline_access"</code> scope
     * is added via this <code>scopes</code> parameter.
     * </p>
     *
     * @return
     *         Scopes to associate with an authorization code and/or an access
     *         token. If a non-null value is set, the original scopes requested
     *         by the client application are replaced.
     *
     * @since 1.4
     */
    String[] getScopes();
}
