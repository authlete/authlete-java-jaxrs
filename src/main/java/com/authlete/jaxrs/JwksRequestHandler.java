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
 * Handler for requests to an endpoint that exposes JSON Web Key Set
 * (<a href="https://tools.ietf.org/html/rfc7517">RFC 7517</a>) document.
 *
 * <p>
 * An OpenID Provider (OP) is required to expose its JSON Web Key Set document
 * (JWK Set) so that client applications can (1) verify signatures by the OP
 * and (2) encrypt their requests to the OP. The URI of a JWK Set endpoint can
 * be found as the value of <b>{@code jwks_uri}</b> in <a href=
 * "http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
 * >OpenID Provider Metadata</a>, if the OP supports <a href=
 * "http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID
 * Connect Discovery 1.0</a>.
 * </p>
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class JwksRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public JwksRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to a JWK Set endpoint. This method internally calls
     * Authlete's {@code /api/service/jwks/get} API.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle() throws WebApplicationException
    {
        try
        {
            // Call Authlete's /api/service/jwks/get API. It returns the JWK Set
            // of the service. Of course, private keys are not included.
            return getApiCaller().serviceJwksGet();
        }
        catch (WebApplicationException e)
        {
            // The API call raised an exception.
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in JwksRequestHandler", t);
        }
    }
}
