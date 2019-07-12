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


import javax.ws.rs.core.Response;
import com.authlete.common.dto.DeviceVerificationResponse;


/**
 * Empty implementation of {@link DeviceVerificationRequestHandlerSpi} interface.
 *
 * @author Hideki Ikeda
 *
 * @since 2.18
 */
public class DeviceVerificationRequestHandlerSpiAdapter implements DeviceVerificationRequestHandlerSpi
{
    @Override
    public String getUserCode()
    {
        return null;
    }


    @Override
    public Response onValid(DeviceVerificationResponse response)
    {
        return null;
    }


    @Override
    public Response onExpired()
    {
        return null;
    }


    @Override
    public Response onNotExist()
    {
        return null;
    }


    @Override
    public Response onServerError()
    {
        return null;
    }
}
