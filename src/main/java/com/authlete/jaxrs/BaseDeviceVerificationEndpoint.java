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
package com.authlete.jaxrs;


import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.jaxrs.spi.DeviceVerificationRequestHandlerSpi;


/**
 * A base class for device verification endpoints.
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public class BaseDeviceVerificationEndpoint extends BaseEndpoint
{
    /**
     * Handle a device verification request.
     *
     * <p>
     * This method internally creates a {@link DeviceVerificationRequestHandler}
     * instance and calls its {@link DeviceVerificationRequestHandler#handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code DeviceVerificationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param spi
     *         An implementation of {@link DeviceVerificationRequestHandlerSpi}.
     *
     * @return
     *         A response that should be returned to the end-user.
     *
     * @since 2.8
     */
    public Response handle(AuthleteApi api, DeviceVerificationRequestHandlerSpi spi)
    {
        try
        {
            // Create a handler.
            DeviceVerificationRequestHandler handler = new DeviceVerificationRequestHandler(api, spi);

            // Delegate the task to the handler.
            return handler.handle();
        }
        catch (WebApplicationException e)
        {
            // An error occurred in the handler.
            onError(e);

            // Convert the error to a Response.
            return e.getResponse();
        }
    }
}
