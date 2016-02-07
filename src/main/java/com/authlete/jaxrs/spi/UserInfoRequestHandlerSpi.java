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
}
