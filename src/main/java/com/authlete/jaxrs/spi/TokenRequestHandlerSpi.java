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
}
