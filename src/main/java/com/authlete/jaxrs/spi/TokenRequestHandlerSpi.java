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


import com.authlete.common.dto.Property;


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
}
