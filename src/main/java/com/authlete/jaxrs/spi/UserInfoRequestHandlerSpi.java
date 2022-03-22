/*
 * Copyright (C) 2016-2022 Authlete, Inc.
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


import java.util.List;
import com.authlete.common.assurance.VerifiedClaims;
import com.authlete.common.assurance.constraint.VerifiedClaimsConstraint;


/**
 * Service Provider Interface to work with {@link
 * com.authlete.jaxrs.UserInfoRequestHandler UserInfoRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor of
 * {@link com.authlete.jaxrs.UserInfoRequestHandler UserInfoRequestHandler}
 * class.
 * </p>
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public interface UserInfoRequestHandlerSpi
{
    /**
     * Prepare claim values of the user who is identified by the subject
     * (= unique identifier).
     *
     * <p>
     * This method is called before calls of {@link #getUserClaim(String, String)}
     * method.
     * </p>
     *
     * @param subject
     *         The subject (= unique identifier) of the user.
     *
     * @param claimNames
     *         Names of the requested claims. Each claim name may contain
     *         a language tag. See "<a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts"
     *         >5.2. Claims Languages and Scripts</a>" in <a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html"
     *         >OpenID Connect Core 1.0</a> for details.
     */
    void prepareUserClaims(String subject, String[] claimNames);


    /**
     * Get the value of a claim of the user.
     *
     * <p>
     * This method may be called multiple times.
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
     * Get the verified claims of the user to be embedded in the userinfo response.
     *
     * <p>
     * <b>NOTE</b>: Since version 2.42, this method is called only when the
     * {@link com.authlete.jaxrs.UserInfoRequestHandler.Params#isOldIdaFormatUsed()
     * isOldIdaFormatUsed()} method of
     * {@link com.authlete.jaxrs.UserInfoRequestHandler.Params
     * UserInfoRequestHandler.Params} returns true. See the description
     * of the method for details.
     * </p>
     *
     * <p>
     * An authorization request may contain a {@code "claims"} request parameter.
     * The value of the request parameter is JSON which conforms to the format
     * defined in <a href=
     * "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter"
     * >5.5. Requesting Claims using the "claims" Request Parameter</a> of
     * <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a>. The JSON may contain a {@code "userinfo"} property.
     * The value of the property is a JSON object which lists claims that the
     * client application wants to be embedded in the userinfo response. The
     * following is an example shown in the section.
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
     * {@code "userinfo"} property like below.
     * </p>
     *
     * <pre>
     * {
     *   "userinfo": {
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
     *         The subject of the user.
     *
     * @param constraint
     *         An object that represents the {@code "verified_claims"} in the
     *         {@code "userinfo"} property.
     *
     * @return
     *         The verified claims. The returned value is embedded in the userinfo
     *         response as the value of the {@code "verified_claims"} claim.
     *         If this method returns null, the {@code "verified_claims"} claim
     *         does not appear in the userinfo response.
     *
     * @since 2.25
     *
     * @see #getVerifiedClaims(String, Object)
     *
     * @deprecated
     */
    @Deprecated
    List<VerifiedClaims> getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint);


    /**
     * Get the verified claims of the user to be embedded in the userinfo response.
     *
     *
     * <p>
     * An authorization request may contain a {@code "claims"} request parameter.
     * The value of the request parameter is JSON which conforms to the format
     * defined in <a href=
     * "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter"
     * >5.5. Requesting Claims using the "claims" Request Parameter</a> of
     * <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID
     * Connect Core 1.0</a>. The JSON may contain an {@code "userinfo"} property.
     * The value of the property is a JSON object which lists claims that the
     * client application wants to be embedded in the userinfo response. The
     * following is an example shown in the section.
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
     * {@code "userinfo"} property like below.
     * </p>
     *
     * <pre>
     * {
     *   "userinfo": {
     *     "verified_claims": {
     *       "verification": {
     *         "trust_framework": null,
     *         "time": null,
     *         "evidence": [
     *           {
     *             "type": {
     *               "value": "document"
     *             },
     *             "method": null,
     *             "document_details": {
     *               "type": null
     *             }
     *           }
     *         ]
     *       },
     *       "claims": {
     *         "given_name": null,
     *         "family_name": null,
     *         "birthdate": null
     *       }
     *     }
     *   }
     * }
     * </pre>
     *
     * <p>
     * The second argument ({@code verifiedClaimsRequest}) of this method
     * represents the value of {@code "verified_claims"} in the request.
     * It is a {@code Map} instance or a {@code List} instance. The latter
     * case happens when the value of {@code "verified_claims"} is a JSON
     * array like below.
     * </p>
     *
     * <pre>
     * {
     *   "userinfo": {
     *     "verified_claims": [
     *       {
     *         "verification": {
     *           "trust_framework": {
     *             "value": "gold"
     *           },
     *           "evidence": [
     *             {
     *               "type": {
     *                 "value": "document"
     *               }
     *             }
     *           ]
     *         },
     *         "claims": {
     *           "given_name": null,
     *           "family_name": null
     *         }
     *       },
     *       {
     *         "verification": {
     *           "trust_framework": {
     *             "values": [
     *               "silver",
     *               "bronze"
     *             ]
     *           },
     *           "evidence": [
     *             {
     *               "type": {
     *                 "value": "vouch"
     *               }
     *             }
     *           ]
     *         },
     *         "claims": {
     *           "given_name": null,
     *           "family_name": null
     *         }
     *       }
     *     ]
     *   }
     * }
     * </pre>
     *
     * <p>
     * When the given argument is a {@code Map} instance, it can be cast by
     * {@code Map<String, Object>}. On the other hand, in the case of a
     * {@code List} instance, each element in the list can be cast by
     * {@code Map<String, Object>}.
     * </p>
     *
     * <p>
     * This method should return a {@code Map} instance or a {@code List}
     * instance which represents the value of {@code "verified_claims"}. The
     * value will be embedded in the userinfo response as the value of
     * {@code "verified_claims"}.
     * </p>
     *
     * <p>
     * For example, to make a userinfo response include
     * {@code "verified_claims"} like below,
     * </p>
     *
     * <pre>
     * "verified_claims": {
     *   "verification": {
     *     "trust_framework": "trust_framework_example"
     *   },
     *   "claims": {
     *     "given_name": "Max",
     *     "family_name": "Meier"
     *   }
     * }
     * </pre>
     *
     * this method should build a {@code Map} instance like below and return it.
     *
     * <pre>
     * Map&lt;String, Object&gt; verification = new HashMap&lt;&gt;();
     * verification.put("trust_framework", "trust_framework_example");
     *
     * Map&lt;String, Object&gt; claims = new HashMap&lt;&gt;();
     * claims.put("given_name", "Max");
     * claims.put("family_name", "Meier");
     *
     * Map&lt;String, Object&gt; verified_claims = new HashMap&lt;&gt;();
     * verified_claims.put("verification", verification);
     * verified_claims.put("claims", claims);
     *
     * return verified_claims;
     * </pre>
     *
     * @param subject
     *         The subject of the user. The same value returned by
     *         {@link #getUserSubject()}.
     *
     * @param verifiedClaimsRequest
     *         An object that represents the {@code "verified_claims"} in the
     *         {@code "userinfo"} property in the {@code "claims"} request
     *         parameter. Either a {@code Map} instance or a {@code List}
     *         instance.
     *
     * @return
     *         The verified claims. The returned value is embedded in the
     *         userinfo response as the value of {@code "verified_claims"}.
     *         If this method returns null, {@code "verified_claims"} does
     *         not appear in the userinfo response.
     *
     * @since 2.42
     *
     * @see <a href="https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html"
     *      >OpenID Connect for Identity Assurance 1.0</a>
     */
    Object getVerifiedClaims(String subject, Object verifiedClaimsRequest);
}
