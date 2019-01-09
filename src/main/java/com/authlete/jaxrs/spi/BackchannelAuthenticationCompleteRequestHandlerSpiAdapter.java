/*
 * Copyright (C) 2019 Authlete, Inc.
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


import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest.Result;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.Property;


/**
 * Empty implementation of {@link BackchannelAuthenticationCompleteRequestHandlerSpi} interface.
 *
 * @since 2.13
 *
 * @author Hideki Ikeda
 */
public class BackchannelAuthenticationCompleteRequestHandlerSpiAdapter implements BackchannelAuthenticationCompleteRequestHandlerSpi
{
    @Override
    public Result getResult()
    {
        return null;
    }


    @Override
    public String getUserSubject()
    {
        return null;
    }


    public long getUserAuthenticatedAt()
    {
        return 0;
    }


    @Override
    public String getAcr()
    {
        return null;
    }


    @Override
    public Object getUserClaim(String claimName)
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
    public void sendNotification(BackchannelAuthenticationCompleteResponse info)
    {
    }
}
