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
     * @return
     *         The time when the end-user authentication occurred.
     *         The number of seconds since Unix epoch (1970-01-01).
     *         Return 0 if the time is unknown.
     */
    long getUserAuthenticatedAt();


    /**
     * Get the subject (= unique identifier) of the end-user.
     *
     * <p>
     * In a typical case, the subject is a primary key or another
     * unique ID of the record that represents the end-user in
     * your user database.
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
}
