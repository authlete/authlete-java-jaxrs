/*
 * Copyright (C) 2016-2024 Authlete, Inc.
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
     * Handle a revocation request.
     *
     * <p>
     * This method internally creates a {@link RevocationRequestHandler} instance
     * and calls its {@link RevocationRequestHandler#handle(MultivaluedMap, String)
     * handle()} method with the {@code parameters} argument and the {@code authorization}
     * argument. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code RevocationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You
     * can override the method as necessary. After calling {@code onError()} method,
     * this method calls {@code getResponse()} method of the exception and uses the
     * returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         Request parameters of a revocation request.
     *
     * @param authorization
     *         The value of {@code Authorization} header.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(AuthleteApi api, MultivaluedMap<String, String> parameters, String authorization)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                ;

        return handle(api, params);
    }


    public Response handle(AuthleteApi api, Params params)
    {
        try
        {
            // Create a handler.
            RevocationRequestHandler handler = new RevocationRequestHandler(api);

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
