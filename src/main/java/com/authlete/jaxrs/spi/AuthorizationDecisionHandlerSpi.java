/*
 * Copyright (C) 2016-2019 Authlete, Inc.
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


import com.authlete.common.assurance.VerifiedClaims;
import com.authlete.common.assurance.constraint.VerifiedClaimsConstraint;
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


    /**
     * Get the value of the "sub" claim to be used in the id_token.
     *
     * <p>
     * If doing a pairwise subject derivation, this method should check the
     * registration of the current Client to see if it has a PAIRWISE subject
     * identifier type. If so, it returns the calculated string of that subject.
     * If not, it returns {@code null} and the value of {@link #getUserSubject()}
     * is used by the API instead.
     * </p>
     *
     * @return
     *         The value of the "sub" claim to be used in the id_token,
     *         or {@code null} if no such subject exists.
     *
     * @since 2.22
     */
    String getSub();


    /**
     * Get the verified claims of the user to be embedded in the ID token.
     *
     * <p>
     * An authorization request may contain a {@code "claims"} request parameter.
     * The value of the request parameter is JSON which conforms to the format
     * defined in <a href=
     * "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter"
     * >5.5. Requesting Claims using the "claims" Request Parameter</a> of
     * <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a>. The JSON may contain an {@code "id_token"} property.
     * The value of the property is a JSON object which lists claims that the
     * client application wants to be embedded in the ID token. The following
     * is an example shown in the section.
     * </p>
     *
     * <pre>
     * {
     *  "userinfo":
     *   {
     *    "given_name": {"essential": true},
     *    "nickname": null,
     *    "email": {"essential": true},
     *    "email_verified": {"essential": true},
     *    "picture": null,
     *    "http://example.info/claims/groups": null
     *   },
     *  "id_token":
     *   {
     *    "auth_time": {"essential": true},
     *    "acr": {"values": ["urn:mace:incommon:iap:silver"] }
     *   }
     * }
     * </pre>
     *
     * <p>
     * <a href="https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html"
     * >OpenID Connect for Identity Assurance 1.0</a> has extended this mechanism
     * to allow client applications to request <b>verified claims</b>. To request
     * verified claims, a {@code "verified_claims"} property is included in the
     * {@code "id_token"} property like below.
     * </p>
     *
     * <pre>
     * {
     *   "id_token": {
     *     "verified_claims": {
     *       "verification": {
     *         "trust_framework": {
     *           "value": "de_aml"
     *         },
     *         "evidence": [
     *           {
     *             "type": {
     *               "value": "id_document"
     *             },
     *             "method": {
     *               "value": "pipp"
     *             },
     *             "document": {
     *               "type": {
     *                 "values": [
     *                   "idcard",
     *                   "passport"
     *                 ]
     *               }
     *             }
     *           }
     *         ]
     *       },
     *       "claims": {
     *         "given_name": null,
     *         "family_name": {
     *           "essential": true
     *         },
     *         "birthdate": {
     *           "purpose": "To send you best wishes on your birthday"
     *         }
     *       }
     *     }
     *   }
     * }
     * </pre>
     *
     * <p>
     * This method should return the requested verified claims.
     * </p>
     *
     * @param subject
     *         The subject of the user. The same value returned by
     *         {@link #getUserSubject()}.
     *
     * @param constraint
     *         An object that represents the {@code "verified_claims"} in the
     *         {@code "id_token"} property.
     *
     * @return
     *         The verified claims. The returned value is embedded in the ID
     *         token as the value of the {@code "verified_claims"} claim.
     *         If this method returns null, the {@code "verified_claims"} claim
     *         does not appear in the ID token.
     *
     * @since 2.25
     */
    VerifiedClaims getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint);
}
