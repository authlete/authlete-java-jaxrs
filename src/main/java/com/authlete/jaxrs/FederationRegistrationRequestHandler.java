/*
 * Copyright (C) 2022-2025 Authlete, Inc.
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
import com.authlete.common.dto.FederationRegistrationRequest;
import com.authlete.common.dto.FederationRegistrationResponse;
import com.authlete.common.dto.FederationRegistrationResponse.Action;


/**
 * Handler for requests to the federation registration endpoint.
 *
 * <p>
 * This class can be used to implement the federation registration endpoint
 * ({@code federation_registration_endpoint}) of the service.
 * </p>
 *
 * @since 2.53
 * @since Authlete 2.3
 *
 * @see <a href="https://openid.net/specs/openid-connect-federation-1_0.html"
 *      >OpenID Connect Federation 1.0</a>
 */
public class FederationRegistrationRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public FederationRegistrationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to the federation registration endpoint. This method is
     * an alias of {@link #handle(FederationRegistrationRequest, Options) handle}{@code
     * (request, null)}.
     *
     * @param request
     *         An "explicit" client registration request.
     *
     * @return
     *         A response that should be returned from the federation
     *         registration endpoint.
     *
     * @throws WebApplicationException
     */
    public Response handle(FederationRegistrationRequest request) throws WebApplicationException
    {
        return handle(request, null);
    }


    /**
     * Handle a request to the federation registration endpoint.
     *
     * @param request
     *         An "explicit" client registration request.
     *
     * @param options
     *         The request options for the {@code /api/federation/registration} API.
     *
     * @return
     *         A response that should be returned from the federation
     *         registration endpoint.
     *
     * @throws WebApplicationException
     *
     * @since 2.82
     */
    public Response handle(
            FederationRegistrationRequest request, Options options) throws WebApplicationException
    {
        // Call Authlete's /api/federation/registration API.
        FederationRegistrationResponse response =
                getApiCaller().callFederationRegistration(request, options);

        // 'action' in the response denotes the next action which
        // the implementation of the endpoint should take.
        Action action = response.getAction();

        // The content of the response.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case OK:
                // 200 OK; application/entity-statement+jwt
                return ResponseUtil.entityStatement(content);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            case NOT_FOUND:
                // 404 Not Found
                return ResponseUtil.notFound(content);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            default:
                // This should not happen.
                throw getApiCaller().unknownAction("/api/federation/registration", action);
        }
    }
}
