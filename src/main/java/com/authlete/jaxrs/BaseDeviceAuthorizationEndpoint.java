/*
 * Copyright (C) 2019-2024 Authlete, Inc.
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
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.jaxrs.DeviceAuthorizationRequestHandler.Params;


/**
 * A base class for device authorization endpoints.
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public class BaseDeviceAuthorizationEndpoint extends BaseEndpoint
{
    /**
     * Handle a device authorization request.
     *
     * <p>
     * This method internally creates a {@link DeviceAuthorizationRequestHandler}
     * instance and calls its {@link DeviceAuthorizationRequestHandler#handle(MultivaluedMap, String, String[])}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code DeviceAuthorizationRequestHandler.handle()} method raises a
     * {@link WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code
     * onError()} does nothing. You can override the method as necessary. After
     * calling {@code onError()} method, this method calls {@code getResponse()}
     * method of the exception and uses the returned value as a response from this
     * method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param spi
     *         An implementation of {@link DeviceAuthorizationRequestHandlerSpi}.
     *
     * @param parameters
     *         Request parameters of the device authorization request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the device authorization
     *         request.
     *
     * @param clientCertificatePath
     *         The certificate path used in mutual TLS authentication, in PEM format.
     *         The client's own certificate is the first in this array. Can be
     *         {@code null}.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters, String authorization,
            String[] clientCertificatePath)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(api, params);
    }


    public Response handle(AuthleteApi api, Params params)
    {
        try
        {
            // Create a handler.
            DeviceAuthorizationRequestHandler handler = new DeviceAuthorizationRequestHandler(api);

            // Delegate the task to the handler.
            return handler.handle(params);
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
