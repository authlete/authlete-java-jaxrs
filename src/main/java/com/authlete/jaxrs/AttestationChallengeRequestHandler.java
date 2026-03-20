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
import com.authlete.common.dto.AttestationChallengeResponse;
import com.authlete.common.dto.AttestationChallengeResponse.Action;


/**
 * Handler for requests to the challenge endpoint of the authorization server.
 *
 * @since 2.93
 * @since Authlete 3.0.28
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/">
 *      OAuth 2.0 Attestation-Based Client Authentication</a>
 */
public class AttestationChallengeRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public AttestationChallengeRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to the challenge endpoint. This method is an alias of the
     * {@link #handle(AttestationChallengeRequest, Options) handle}{@code (request, null)}.
     *
     * @param request
     *         A request to the challenge endpoint.
     *
     * @return
     *         A response that should be returned from the challenge endpoint
     *
     * @throws WebApplicationException
     */
    public Response handle(
            AttestationChallengeRequest request) throws WebApplicationException
    {
        return handle(request, null);
    }


    /**
     * Handle a request to the challenge endpoint.
     *
     * @param request
     *         A request to the challenge endpoint.
     *
     * @param options
     *         The request options for the
     *         {@code /api/<service-id>/attestation/challenge} API.
     *
     * @return
     *         A response that should be returned from the challenge endpoint.
     *
     * @throws WebApplicationException
     */
    public Response handle(
            AttestationChallengeRequest request, Options options) throws WebApplicationException
    {
        // Call Authlete's /attestation/challenge API.
        AttestationChallengeResponse response =
                getApiCaller().callAttestationChallenge(request, options);

        // 'action' in the response denotes the next action which
        // the implementation of the endpoint should take.
        Action action = response.getAction();

        // The content of the response.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case OK:
                // 200 OK; application/json
                return ResponseUtil.ok(content);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            default:
                // This should not happen.
                throw getApiCaller().unknownAction("/attestation/challenge", action);
        }
    }
}
