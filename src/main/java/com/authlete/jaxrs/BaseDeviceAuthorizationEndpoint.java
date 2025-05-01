/*
 * Copyright (C) 2019-2025 Authlete, Inc.
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
import com.authlete.common.api.Options;
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
     * Handle a device authorization request. This method is an alias of {@link
     * #handle(AuthleteApi, MultivaluedMap, String, String[], Options) handle}{@code
     * (api, parameters, authorization, clientCertificatePath, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         The request parameters of the device authorization request.
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
        return handle(api, parameters, authorization, clientCertificatePath, null);
    }


    /**
     * Handle a device authorization request. This method is an alias of the {@link
     * #handle(AuthleteApi, Params, Options)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
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
     * @param options
     *         The request options for the device authorization request.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters, String authorization,
            String[] clientCertificatePath, Options options)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(api, params, options);
    }


    /**
     * Handle a device authorization request. This method is an alias of {@link
     * #handle(AuthleteApi,Params, Options) handle}{@code (api, params, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         Parameters for Authlete's {@code /device/authorization} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.79
     */
    public Response handle(AuthleteApi api, Params params)
    {
        return handle(api, params, null);
    }


    /**
     * Handle a device authorization request.
     *
     * <p>
     * This method internally creates a {@link DeviceAuthorizationRequestHandler}
     * instance and calls its {@link DeviceAuthorizationRequestHandler#handle(Params, Options)}
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
     * @param params
     *         The request parameters for Authlete's {@code /api/device/authorization} API.
     *
     * @param options
     *         The request options for the {@code /api/device/authorization} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handle(AuthleteApi api, Params params, Options options)
    {
        try
        {
            // Create a handler.
            DeviceAuthorizationRequestHandler handler =
                    new DeviceAuthorizationRequestHandler(api);

            // Delegate the task to the handler.
            return handler.handle(params, options);
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
