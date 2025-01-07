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
import com.authlete.common.dto.FederationConfigurationRequest;
import com.authlete.common.dto.FederationConfigurationResponse;
import com.authlete.common.dto.FederationConfigurationResponse.Action;


/**
 * Handler for requests to the entity configuration endpoint.
 *
 * <p>
 * This class can be used to implement the entity configuration endpoint
 * ({@code /.well-known/openid-federation}) of the service.
 * </p>
 *
 * @since 2.49
 * @since Authlete 2.3
 *
 * @see <a href="https://openid.net/specs/openid-connect-federation-1_0.html"
 *      >OpenID Connect Federation 1.0</a>
 */
public class FederationConfigurationRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public FederationConfigurationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to the entity configuration endpoint. This method is an
     * alias of {@link #handle(FederationConfigurationRequest, Options) handle}{@code
     * (request, null)}.
     *
     * @param request
     *         An entity configuration request.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     *
     * @throws WebApplicationException
     */
    public Response handle(FederationConfigurationRequest request) throws WebApplicationException
    {
        return handle(request, null);
    }


    /**
     * Handle a request to the entity configuration endpoint.
     *
     * @param request
     *         An entity configuration request.
     *
     * @param options
     *         The request options for the {@code /api/federation/configuration} API.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     *
     * @throws WebApplicationException
     *
     * @since 2.82
     */
    public Response handle(
            FederationConfigurationRequest request, Options options) throws WebApplicationException
    {
        // Call Authlete's /api/federation/configuration API.
        FederationConfigurationResponse response =
                getApiCaller().callFederationConfiguration(request, options);

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

            case NOT_FOUND:
                // 404 Not Found
                return ResponseUtil.notFound(content);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            default:
                // This should not happen.
                throw getApiCaller().unknownAction("/api/federation/configuration", action);
        }
    }
}
