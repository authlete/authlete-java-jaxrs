/*
 * Copyright (C) 2023-2025 Authlete, Inc.
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
import com.authlete.common.dto.CredentialIssuerMetadataRequest;
import com.authlete.common.dto.CredentialIssuerMetadataResponse;
import com.authlete.common.dto.CredentialIssuerMetadataResponse.Action;


/**
 * Handler for requests to the credential issuer metadata endpoint.
 *
 * <p>
 * This class can be used to implement the credential issuer metadata endpoint
 * ({@code /.well-known/openid-credential-issuer}) of the service.
 * </p>
 *
 * @since 2.57
 * @since Authlete 3.0
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 *      >OpenID for Verifiable Credential Issuance</a>
 */
public class CredentialIssuerMetadataRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public CredentialIssuerMetadataRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to the credential issuer metadata endpoint. This method
     * is an alias of the {@link
     * #handle(CredentialIssuerMetadataRequest, Options) handle}{@code (request, null)}.
     *
     * @param request
     *         A credential issuer metadata request.
     *
     * @return
     *         A response that should be returned from the credential issuer
     *         metadata endpoint.
     *
     * @throws WebApplicationException
     */
    public Response handle(
            CredentialIssuerMetadataRequest request) throws WebApplicationException
    {
        return handle(request, null);
    }


    /**
     * Handle a request to the credential issuer metadata endpoint.
     *
     * @param request
     *         A credential issuer metadata request.
     *
     * @param options
     *         The request options for the {@code /api/vci/metadata} API.
     *
     * @return
     *         A response that should be returned from the credential issuer
     *         metadata endpoint.
     *
     * @throws WebApplicationException
     *
     * @since 2.82
     */
    public Response handle(
            CredentialIssuerMetadataRequest request, Options options) throws WebApplicationException
    {
        // Call Authlete's /vci/metadata API.
        CredentialIssuerMetadataResponse response =
                getApiCaller().callCredentialIssuerMetadata(request, options);

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

            case NOT_FOUND:
                // 404 Not Found
                return ResponseUtil.notFound(content);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            default:
                // This should not happen.
                throw getApiCaller().unknownAction("/vci/metadata", action);
        }
    }
}
