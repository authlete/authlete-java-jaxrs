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


import javax.ws.rs.core.Response;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Property;


/**
 * Empty implementation of {@link AuthorizationRequestHandlerSpi} interface.
 *
 * <p>
 * If you have no mind to support {@code prompt=none} (<a href=
 * "http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
 * >3.1.2.1. Authentication Request</a> in <a href=
 * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
 * Connect Core 1.0</a>), methods you must override are only
 * {@link #generateAuthorizationPage(AuthorizationResponse)}.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class AuthorizationRequestHandlerSpiAdapter implements AuthorizationRequestHandlerSpi
{
    @Override
    public boolean isUserAuthenticated()
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
    public Response generateAuthorizationPage(AuthorizationResponse info)
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
}
