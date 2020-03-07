/*
 * Copyright (C) 2016-2020 Authlete, Inc.
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
import com.authlete.jaxrs.TokenRequestHandler.Params;
import com.authlete.jaxrs.spi.TokenRequestHandlerSpi;


/**
 * A base class for token endpoints.
 *
 * @since 1.2
 *
 * @see <a href="http://tools.ietf.org/html/rfc6749#section-3.2"
 *      >RFC 6749, 3.2. Token Endpoint</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridTokenEndpoint"
 *      >OpenID Connect Core 1.0, 3.3.3. Token Endpoint</a>
 *
 * @author Takahiko Kawasaki
 */
public class BaseTokenEndpoint extends BaseEndpoint
{
    /**
     * Handle a token request.
     *
     * This method is an alias of the {@link #handle(AuthleteApi,
     * TokenRequestHandlerSpi, Params)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param spi
     *         An implementation of {@link TokenRequestHandlerSpi}.
     *
     * @param parameters
     *         Request parameters of the token request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the token request.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(
            AuthleteApi api, TokenRequestHandlerSpi spi,
            MultivaluedMap<String, String> parameters, String authorization)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                ;

        return handle(api, spi, params);
    }


    /**
     * Handle a token request.
     *
     * This method is an alias of the {@link #handle(AuthleteApi,
     * TokenRequestHandlerSpi, Params)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param spi
     *         An implementation of {@link TokenRequestHandlerSpi}.
     *
     * @param parameters
     *         Request parameters of the token request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the token request.
     *
     * @param clientCertificatePath
     *         The certificate path used in mutual TLS authentication, each in
     *         PEM format. The client's own certificate is the first in this
     *         array. Can be {@code null}.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.8
     */
    public Response handle(
            AuthleteApi api, TokenRequestHandlerSpi spi,
            MultivaluedMap<String, String> parameters, String authorization, String[] clientCertificatePath)
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(api, spi, params);
    }


    /**
     * Handle a token request.
     *
     * <p>
     * This method internally creates a {@link TokenRequestHandler} instance and
     * calls its {@link TokenRequestHandler#handle(Params)}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code TokenRequestHandler.handle()} method raises a {@link
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
     *         An implementation of {@link TokenRequestHandlerSpi}.
     *
     * @param params
     *         Parameters needed to handle the token request.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.27
     */
    public Response handle(
            AuthleteApi api, TokenRequestHandlerSpi spi, Params params)
    {
        try
        {
            // Create a handler.
            TokenRequestHandler handler = new TokenRequestHandler(api, spi);

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
