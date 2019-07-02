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


import java.net.URI;
import javax.ws.rs.core.Response;
import com.authlete.common.dto.DeviceCompleteRequest.Result;
import com.authlete.common.dto.Property;


/**
 * Empty implementation of {@link DeviceCompleteRequestHandlerSpi} interface.
 *
 * @author Hideki Ikeda
 */
public class DeviceCompleteRequestHandlerSpiAdapter implements DeviceCompleteRequestHandlerSpi
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


    @Override
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
    public String[] getScopes()
    {
        return null;
    }


    @Override
    public Property[] getProperties()
    {
        return null;
    }


    @Override
    public String getErrorDescription()
    {
        return null;
    }


    @Override
    public URI getErrorUri()
    {
        return null;
    }


    @Override
    public Response onSuccess()
    {
        return null;
    }


    @Override
    public Response onInvalidRequest()
    {
        return null;
    }


    @Override
    public Response onUserCodeExpired()
    {
        return null;
    }


    @Override
    public Response onUserCodeNotExist()
    {
        return null;
    }


    @Override
    public Response onServerError()
    {
        return null;
    }
}
