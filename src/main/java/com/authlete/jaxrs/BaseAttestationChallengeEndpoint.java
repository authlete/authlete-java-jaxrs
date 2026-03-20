/*
 * Copyright (C) 2026 Authlete, Inc.
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
import com.authlete.common.api.Options;
import com.authlete.common.dto.AttestationChallengeRequest;


/**
 * A base class for the challenge endpoint of the authorization server defined in
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/"
 * >OAuth 2&#x2E;0 Attestation-Based Client Authentication</a>.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">
 *      OAuth 2.0 Attestation-Based Client Authentication</a>
 *
 * @since 2.93
 * @since Authlete 3.0.28
 */
public class BaseAttestationChallengeEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the challenge endpoint. This method is
     * an alias of {@link #handle(AuthleteApi, Options) handle}{@code (api, (Options)null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the challenge endpoint.
     */
    public Response handle(AuthleteApi api)
    {
        return handle(api, (Options)null);
    }


    /**
     * Handle a request to the challenge endpoint. This method is an alias of the
     * {@link #handle(AuthleteApi, AttestationChallengeRequest, Options)
     * handle}{@code (api, new AttestationChallengeRequest(), options)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param options
     *         The request options for the
     *         {@code /api/<service-id>/attestation/challenge} API.
     *
     * @return
     *         A response that should be returned from the challenge endpoint.
     */
    public Response handle(AuthleteApi api, Options options)
    {
        return handle(api, new AttestationChallengeRequest(), options);
    }


    /**
     * Handle a request to the challenge endpoint. This method is an alias of
     * {@link #handle(AuthleteApi, AttestationChallengeRequest, Options)
     * handle}{@code (api, request, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param request
     *         The request parameters for Authlete's
     *         {@code /api/<service-id>/attestation/challenge} API.
     *
     * @return
     *         A response that should be returned from the challenge endpoint.
     */
    public Response handle(AuthleteApi api, AttestationChallengeRequest request)
    {
        return handle(api, request, null);
    }


    /**
     * Handle a request to the challenge endpoint.
     *
     * <p>
     * This method internally creates a {@link AttestationChallengeRequestHandler}
     * instance and calls its {@link AttestationChallengeRequestHandler#handle(AttestationChallengeRequest,
     * Options) handle()} method. Then, this method uses the value returned from
     * the handler's method as a response from this method.
     * </p>
     *
     * <p>
     * When the handler's method raises a {@link WebApplicationException}, this
     * method calls {@link #onError(WebApplicationException) onError()} method
     * with the exception. The default implementation of {@code onError()} does
     * nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method
     * of the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param request
     *         The request parameters for Authlete's
     *         {@code /api/<service-id>/attestation/challenge} API.
     *
     * @param options
     *         The request options for the
     *         {@code /api/<service-id>/attestation/challenge} API.
     *
     * @return
     *         A response that should be returned from the challenge endpoint.
     */
    public Response handle(
            AuthleteApi api, AttestationChallengeRequest request, Options options)
    {
        try
        {
            // Create a handler.
            AttestationChallengeRequestHandler handler =
                    new AttestationChallengeRequestHandler(api);

            // Delegate the task to the handler.
            return handler.handle(request, options);
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
