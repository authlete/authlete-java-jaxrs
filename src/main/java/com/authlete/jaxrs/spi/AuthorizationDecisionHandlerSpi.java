/*
 * Copyright (C) 2016 Authlete, Inc.
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
 * com.authlete.jaxrs.AuthorizationDecisionHandler AuthorizationDecisionHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.AuthorizationDecisionHandler
 * AuthorizationDecisionHandler} class.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public interface AuthorizationDecisionHandlerSpi
{
    /**
     * Get the decision on the authorization request.
     *
     * @return
     *         {@code true} if the end-user has decided to grant
     *         authorization to the client application. Otherwise,
     *         {@code false}.
     */
    boolean isClientAuthorized();


    /**
     * Get the time when the end-user was authenticated.
     *
     * <p>
     * For example, if an authorization always requires an end-user
     * to login, the authentication time is always "just now", so
     * the implementation of this method will be like the following.
     * </p>
     *
     * <blockquote>
     * <pre style="border: 1px solid gray; padding: 0.5em; margin: 1em;">
     * <span style="color: gray;">&#x40;Override</span>
     * <span style="color: purple; font-weight: bold;">public long</span> getUserAuthenticatedAt()
     * {
     *     <span style="color: purple; font-weight: bold;">return</span> System.currentTimeMillis() / 1000;
     * }</pre>
     * </blockquote>
     *
     * <p>
     * This method is not called when {@link #isClientAuthorized()}
     * has returned {@code false}.
     * </p>
     *
     * @return
     *         The time when the end-user authentication occurred.
     *         The number of seconds since Unix epoch (1970-01-01).
     *         Return 0 if the time is unknown.
     */
    long getUserAuthenticatedAt();


    /**
     * Get the subject (= unique identifier) of the end-user.
     * It must consist of only ASCII letters and its length
     * must not exceed 100.
     *
     * <p>
     * In a typical case, the subject is a primary key or another
     * unique ID of the record that represents the end-user in
     * your user database.
     * </p>
     *
     * <p>
     * This method is not called when {@link #isClientAuthorized()}
     * has returned {@code false}.
     * </p>
     *
     * @return
     *         The subject (= unique identifier) of the end-user.
     *         Returning {@code null} makes the authorization
     *         request fail.
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
     * If you don't know what ACR is, return {@code null}.
     * </p>
     *
     * @return
     *         The authentication context class reference (ACR) that
     *         was satisfied when the current end-user was authenticated.
     */
    String getAcr();


    /**
     * Get the value of a claim of the user.
     *
     * <p>
     * This method may be called multiple times. On the other hand,
     * this method is not called when {@link #isClientAuthorized()}
     * has returned {@code false} or when {@link #getUserSubject()}
     * has returned {@code null}.
     * </p>
     *
     * @param claimName
     *         A claim name such as {@code name} and {@code family_name}.
     *         Standard claim names are listed in "<a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims"
     *         >5.1. Standard Claims</a>" of <a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     *         Connect Core 1.0</a>. Java constant values that represent the
     *         standard claims are listed in {@link com.authlete.common.types.StandardClaims
     *         StandardClaims} class. The value of {@code claimName} does NOT
     *         contain a language tag.
     *
     * @param languageTag
     *         A language tag such as {@code en} and {@code ja}. Implementations
     *         should take this into account whenever possible. See "<a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts"
     *         >5.2. Claims Languages and Scripts</a>" in <a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     *         Connect Core 1.0</a> for details.
     *
     * @return
     *         The claim value. {@code null} if the claim value of the claim
     *         is not available.
     */
    Object getUserClaim(String claimName, String languageTag);


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
     * @return
     *         Extra properties. If {@code null} is returned, any extra property will
     *         not be associated.
     *
     * @since 1.3
     */
    Property[] getProperties();
}
