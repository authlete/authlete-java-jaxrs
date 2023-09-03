/*
 * Copyright (C) 2017-2023 Authlete, Inc.
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
import com.authlete.jaxrs.IntrospectionRequestHandler.Params;


/**
 * A base class for introspection endpoint implementations.
 *
 * @see <a href="http://tools.ietf.org/html/rfc7662"
 *      >RFC 7662 : OAuth 2.0 Token Introspection</a>
 *
 * @see IntrospectionRequestHandler
 *
 * @since 2.2
 *
 * @author Takahiko Kawasaki
 */
public class BaseIntrospectionEndpoint extends BaseEndpoint
{
    /**
     * Handle an introspection request.
     *
     * This method is an alias of the {@link #handle(AuthleteApi,
     * IntrospectionRequestHandler.Params)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param parameters
     *         Request parameters of an introspection request.
     *
     * @return
     *         A response that should be returned to the resource server.
     */
    public Response handle(AuthleteApi api, MultivaluedMap<String, String> parameters)
    {
        Params params = new Params()
                .setParameters(parameters)
                ;

        return handle(api, params);
    }


    /**
     * Handle an introspection request.
     *
     * <p>
     * This method internally creates an {@link IntrospectionRequestHandler}
     * instance and calls its {@link IntrospectionRequestHandler#handle(IntrospectionRequestHandler.Params)
     * handle()} method with the {@code params} argument. Then, this
     * method uses the value returned from the {@code handle()} method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When {@code IntrospectionRequestHandler.handle()} method raises a
     * {@link WebApplicationException}, this method calls {@link
     * #onError(WebApplicationException) onError()} method with the exception.
     * The default implementation of {@code onError()} does nothing.
     * You can override the method as necessary. After calling {@code
     * onError()} method, this method calls {@code getResponse()} method
     * of the exception and uses the returned value as a response from
     * this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param params
     *         Parameters needed to handle the introspection request.
     *
     * @return
     *         A response that should be returned to the resource server.
     *
     * @since 2.63
     */
    public Response handle(AuthleteApi api, Params params)
    {
        try
        {
            // Create a handler.
            IntrospectionRequestHandler handler = new IntrospectionRequestHandler(api);

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
