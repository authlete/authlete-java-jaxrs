/*
 * Copyright (C) 2023 Authlete, Inc.
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
import com.authlete.common.dto.CredentialJwtIssuerMetadataRequest;


/**
 * A base class for the JWT issuer metadata endpoint
 * ({@code /.well-known/jwt-issuer}) defined in <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/"
 * >SD-JWT-based Verifiable Credentials (SD-JWT VC)</a>.
 *
 * <p>
 * A JWT issuer provides an endpoint that returns its <b>JWT issuer metadata</b>
 * in the JSON format. The URL of the endpoint is defined as follows:
 * </p>
 *
 * <blockquote>
 * JWT Issuer Identifier + {@code /.well-known/jwt-issuer}
 * </blockquote>
 *
 * <p>
 * <b>JWT Issuer Identifier</b> is a URL that identifies the JWT issuer.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/"
 *      >SD-JWT-based Verifiable Credentials (SD-JWT VC)</a>
 *
 * @since 2.65
 * @since Authlete 3.0
 */
public class BaseCredentialJwtIssuerMetadataEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the JWT issuer metadata endpoint.
     *
     * <p>
     * This method internally creates a {@link
     * CredentialJwtIssuerMetadataRequestHandler} instance and calls its {@link
     * CredentialJwtIssuerMetadataRequestHandler#handle(CredentialJwtIssuerMetadataRequest)
     * handle}<code>({@link CredentialJwtIssuerMetadataRequest})</code> method.
     * Then, this method uses the value returned from the handler's method as a
     * response from this method.
     * </p>
     *
     * <p>
     * When the handler's method raises a {@link WebApplicationException}, this
     * method calls {@link #onError(WebApplicationException)
     * onError(WebApplicationException)} method with the exception. The default
     * implementation of {@code onError()} does nothing. You can override the
     * method as necessary. After calling {@code onError()} method, this method
     * calls {@code getResponse()} method of the exception and uses the returned
     * value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the JWT issuer
     *         metadata endpoint.
     */
    public Response handle(AuthleteApi api, CredentialJwtIssuerMetadataRequest request)
    {
        try
        {
            // Create a handler.
            CredentialJwtIssuerMetadataRequestHandler handler =
                    new CredentialJwtIssuerMetadataRequestHandler(api);

            // Delegate the task to the handler.
            return handler.handle(request);
        }
        catch (WebApplicationException e)
        {
            // An error occurred in the handler.
            onError(e);

            // Convert the error to a Response.
            return e.getResponse();
        }
    }


    /**
     * Handle a request to the JWT issuer metadata endpoint.
     *
     * <p>
     * This method is an alias of {@link
     * #handle(AuthleteApi, CredentialJwtIssuerMetadataRequest)
     * handle}{@code (api, new CredentialJwtIssuerMetadataRequest())}
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the JWT issuer
     *         metadata endpoint.
     */
    public Response handle(AuthleteApi api)
    {
        return handle(api, new CredentialJwtIssuerMetadataRequest());
    }
}
