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
import com.authlete.jaxrs.PushedAuthReqHandler.Params;


/**
 * A base class for pushed authorization endpoints.
 *
 * @since 2.21
 *
 * @see <a href="https://tools.ietf.org/html/draft-lodderstedt-oauth-par"
 *      >OAuth 2.0 Pushed Authorization Requests</a>
 *
 * @author Justin Richer
 */
public class BasePushedAuthReqEndpoint extends BaseEndpoint
{
    /**
     * Handle a pushed authorization request. This method is an alias of {@link
     * #handle(AuthleteApi, MultivaluedMap, String, String[], Options) handle}{@code
     * (api, parameters, authorization, clientCertificates, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         The request parameters of the pushed authorization request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the pushed authorization request.
     *
     * @param clientCertificates
     *         The certificate path used in mutual TLS authentication, in PEM format. The
     *         client's own certificate is the first in this array. Can be {@code null}.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    protected Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters,
            String authorization, String[] clientCertificates)
    {
        return handle(api, parameters, authorization, clientCertificates, null);
    }


    /**
     * Handle a pushed authorization request. This method is an alias of the {@link
     * #handle(AuthleteApi, Params, Options)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         The request parameters of the pushed authorization request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the pushed authorization request.
     *
     * @param clientCertificates
     *         The certificate path used in mutual TLS authentication, in PEM format. The
     *         client's own certificate is the first in this array. Can be {@code null}.
     *
     * @param options
     *         The request options for the {@code /api/pushed_auth_req} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    protected Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters,
            String authorization, String[] clientCertificates, Options options)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificates)
                ;

        return handle(api, params, options);
    }


    /**
     * Handle a PAR request. This method is an alias of {@link
     * #handle(AuthleteApi, Params, Options) handle}{@code (api, params, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         Parameters needed to handle the PAR request.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.70
     */
    public Response handle(AuthleteApi api, Params params)
    {
        return handle(api, params, null);
    }


    /**
     * Handle a PAR request.
     *
     * <p>
     * This method internally creates a {@link PushedAuthReqHandler} instance and
     * calls its {@link PushedAuthReqHandler#handle(PushedAuthReqHandler.Params) handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code PushedAuthReqHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException) onError()}
     * method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         The request parameters needed to handle the PAR request.
     *
     * @param options
     *         The request options for the PAR request.
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
            PushedAuthReqHandler handler = new PushedAuthReqHandler(api);

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
