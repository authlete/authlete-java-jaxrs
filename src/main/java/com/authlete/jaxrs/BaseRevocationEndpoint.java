/*
 * Copyright (C) 2016-2025 Authlete, Inc.
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
import com.authlete.jaxrs.RevocationRequestHandler.Params;


/**
 * A base class for revocation endpoint implementations.
 *
 * @see <a href="http://tools.ietf.org/html/rfc7009"
 *      >RFC 7009 : OAuth 2.0 Token Revocation</a>
 *
 * @see RevocationRequestHandler
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class BaseRevocationEndpoint extends BaseEndpoint
{
    /**
     * Handle a revocation request. This method is an alias of {@link
     * #handle(AuthleteApi, MultivaluedMap, String, Options) handle}{@code
     * (api, parameters, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         The request parameters of a revocation request.
     *
     * @param authorization
     *         The value of {@code Authorization} header.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters, String authorization)
    {
        return handle(api, parameters, authorization, null);
    }


    /**
     * Handle a revocation request. This method is an alias of {@link
     * #handle(AuthleteApi, MultivaluedMap, String, Options) handle}{@code
     * (api, parameters, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         The request parameters of a revocation request.
     *
     * @param authorization
     *         The value of {@code Authorization} header.
     *
     * @param options
     *         The request options for the {@code /api/auth/revocation} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handle(
            AuthleteApi api, MultivaluedMap<String, String> parameters, String authorization,
            Options options)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                ;

        return handle(api, params, options);
    }


    /**
     * Handle a revocation request. This method is an alias of {@link
     * #handle(AuthleteApi, MultivaluedMap, String, Options) handle}{@code (api, params, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         Parameters for Authlete's {@code /api/auth/revocation} API.
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
     * Handle a revocation request.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         The request parameters for Authlete's {@code /api/auth/revocation} API.
     *
     * @param options
     *         The request options for Authlete's {@code /api/auth/revocation} API.
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
            RevocationRequestHandler handler = new RevocationRequestHandler(api);

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
