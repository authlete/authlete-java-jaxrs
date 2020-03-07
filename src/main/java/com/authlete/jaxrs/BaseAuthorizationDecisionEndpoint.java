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
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.jaxrs.AuthorizationDecisionHandler.Params;
import com.authlete.jaxrs.spi.AuthorizationDecisionHandlerSpi;


/**
 * A base class for authorization decision endpoints.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class BaseAuthorizationDecisionEndpoint extends BaseEndpoint
{
    /**
     * Handle an authorization decision request.
     *
     * <p>
     * This method internally creates a {@link AuthorizationDecisionHandler} instance and
     * calls its {@link AuthorizationDecisionHandler#handle(String, String[], String[])}
     * method. Then, this method uses the value returned from the {@code handle()} method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When {@code AuthorizationDecisionHandler.handle()} method raises a {@link
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
     * @param spi
     *         An implementation of {@link AuthorizationDecisionHandlerSpi}.
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/auth/authorization} API.
     *
     * @param claimNames
     *         Names of requested claims. Use the value of the {@code claims}
     *         parameter in a response from Authlete's {@code /api/auth/authorization} API.
     *
     * @param claimLocales
     *         Requested claim locales. Use the value of the {@code claimsLocales}
     *         parameter in a response from Authlete's {@code /api/auth/authorization} API.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(
            AuthleteApi api, AuthorizationDecisionHandlerSpi spi,
            String ticket, String[] claimNames, String[] claimLocales)
    {
        Params params = new Params()
                .setTicket(ticket)
                .setClaimNames(claimNames)
                .setClaimLocales(claimLocales)
                ;

        return handle(api, spi, params);
    }


    /**
     * Handle an authorization decision request.
     *
     * <p>
     * This method internally creates a {@link AuthorizationDecisionHandler} instance and
     * calls its {@link AuthorizationDecisionHandler#handle(String, String[], String[])}
     * method. Then, this method uses the value returned from the {@code handle()} method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When {@code AuthorizationDecisionHandler.handle()} method raises a {@link
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
     * @param spi
     *         An implementation of {@link AuthorizationDecisionHandlerSpi}.
     *
     * @param params
     *         Parameters necessary to handle the decision.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.26
     */
    public Response handle(
            AuthleteApi api, AuthorizationDecisionHandlerSpi spi, Params params)
    {
        try
        {
            // Create a handler.
            AuthorizationDecisionHandler handler = new AuthorizationDecisionHandler(api, spi);

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
