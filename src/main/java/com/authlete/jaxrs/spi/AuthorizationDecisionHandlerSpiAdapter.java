/*
 * Copyright (C) 2016-2020 Authlete, Inc.
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
import com.authlete.common.dto.Property;


/**
 * Empty implementation of {@link AuthorizationDecisionHandlerSpi} interface.
 *
 * @author Takahiko Kawasaki
 */
public class AuthorizationDecisionHandlerSpiAdapter implements AuthorizationDecisionHandlerSpi
{
    @Override
    public boolean isClientAuthorized()
    {
        return false;
    }


    @Override
    public long getUserAuthenticatedAt()
    {
        return 0;
    }


    @Override
    public String getUserSubject()
    {
        return null;
    }


    @Override
    public String getAcr()
    {
        return null;
    }


    @Override
    public Object getUserClaim(String claimName, String languageTag)
    {
        return null;
    }


    @Override
    public Property[] getProperties()
    {
        return null;
    }


    @Override
    public String[] getScopes()
    {
        return null;
    }


    @Override
    public String getSub()
    {
        return null;
    }


    @Override
    public List<VerifiedClaims> getVerifiedClaims(String subject, VerifiedClaimsConstraint constraint)
    {
        return null;
    }
}
