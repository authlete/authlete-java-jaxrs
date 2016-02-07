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
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;


/**
 * A base class for JWK Set endpoints.
 *
 * <p>
 * An OpenID Provider (OP) is required to expose its JSON Web Key Set document
 * (JWK Set) so that client applications can (1) verify signatures by the OP
 * and (2) encrypt their requests to the OP. The URI of a JWK Set endpoint can
 * be found as the value of <b>{@code jwks_uri}</b> in <a href=
 * "http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
 * >OpenID Provider Metadata</a> if the OP supports <a href=
 * "http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID
 * Connect Discovery 1.0</a>.
 * </p>
 *
 * @see <a href="http://tools.ietf.org/html/rfc7517"
 *      >RFC 7517, JSON Web Key (JWK)</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.htm"
 *      >OpenID Connect Core 1.0</a>
 *
 * @see <a href="http://openid.net/specs/openid-connect-discovery-1_0.html"
 *      >OpenID Connect Discovery 1.0</a>
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class BaseJwksEndpoint extends BaseEndpoint
{
    /**
     * Handle a request for a JWK Set document.
     *
     * <p>
     * This method internally creates a {@link JwksRequestHandler} instance and
     * calls its {@link JwksRequestHandler#handle()} method. Then, this method
     * uses the value returned from the {@code handle()} method as a response
     * from this method.
     * </p>
     *
     * <p>
     * When {@code JwksRequestHandler.handle()} method raises a {@link
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
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(AuthleteApi api)
    {
        try
        {
            // Create a handler.
            JwksRequestHandler handler = new JwksRequestHandler(api);

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
