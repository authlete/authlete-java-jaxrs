/*
 * Copyright (C) 2016 Authlete, Inc.
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
import com.authlete.jaxrs.spi.AuthorizationRequestHandlerSpi;


/**
 * A base class for authorization endpoints.
 *
 * @since 1.2
 *
 * @see <a href="http://tools.ietf.org/html/rfc6749#section-3.1"
 *      >RFC 6749, 3.1. Authorization Endpoint</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint"
 *      >OpenID Connect Core 1.0, 3.1.2. Authorization Endpoint (Authorization Code Flow)</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthorizationEndpoint"
 *      >OpenID Connect Core 1.0, 3.2.2. Authorization Endpoint (Implicit Flow)</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthorizationEndpoint"
 *      >OpenID Connect Core 1.0, 3.3.2. Authorization Endpoint (Hybrid Flow)</a>
 *
 * @author Takahiko Kawasaki
 */
public class BaseAuthorizationEndpoint extends BaseEndpoint
{
    /**
     * Handle an authorization request.
     *
     * <p>
     * This method internally creates a {@link AuthorizationRequestHandler} instance and
     * calls its {@link AuthorizationRequestHandler#handle(MultivaluedMap)} method.
     * Then, this method uses the value returned from the {@code handle()} method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When {@code AuthorizationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * calls {@code printStackTrace()} of the exception and does nothing else. You
     * can override the method as necessary. After calling {@code onError()} method,
     * this method calls {@code getResponse()} method of the exception and uses the
     * returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param spi
     *         An implementation of {@link AuthorizationRequestHandlerSpi}.
     *
     * @param parameters
     *         Request parameters of the authorization request.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(
            AuthleteApi api, AuthorizationRequestHandlerSpi spi,
            MultivaluedMap<String, String> parameters)
    {
        try
        {
            // Create a handler.
            AuthorizationRequestHandler handler = new AuthorizationRequestHandler(api, spi);

            // Delegate the task to the handler.
            return handler.handle(parameters);
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
