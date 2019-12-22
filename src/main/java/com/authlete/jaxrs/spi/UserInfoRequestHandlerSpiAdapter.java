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


/**
 * Empty implementation of {@link UserInfoRequestHandlerSpi} interface.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class UserInfoRequestHandlerSpiAdapter implements UserInfoRequestHandlerSpi
{
    @Override
    public void prepareUserClaims(String subject, String[] claimNames)
    {
    }


    @Override
    public Object getUserClaim(String claimName, String languageTag)
    {
        return null;
    }


    @Override
    public VerifiedClaims getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)
    {
        return null;
    }
}
