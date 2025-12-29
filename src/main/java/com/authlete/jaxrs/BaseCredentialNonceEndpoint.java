/*
 * Copyright (C) 2025 Authlete, Inc.
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
import com.authlete.common.dto.CredentialNonceRequest;


/**
 * A base class for the nonce endpoint of the credential issuer
 * defined in <a href=
 * "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 * >OpenID for Verifiable Credential Issuance 1&#x2E;0</a>.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 *      >OpenID for Verifiable Credential Issuance</a>
 *
 * @since 2.90
 * @since Authlete 3.0.22
 */
public class BaseCredentialNonceEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the nonce endpoint. This method is
     * an alias of {@link #handle(AuthleteApi, Options) handle}{@code (api, (Options)null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the nonce endpoint.
     */
    public Response handle(AuthleteApi api)
    {
        return handle(api, (Options)null);
    }


    /**
     * Handle a request to the nonce endpoint. This method is an alias of the
     * {@link #handle(AuthleteApi, CredentialNonceRequest, Options)
     * handle}{@code (api, new CredentialNonceRequest(), options)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param options
     *         The request options for the {@code /api/<service-id>/vci/nonce} API.
     *
     * @return
     *         A response that should be returned from the nonce endpoint.
     */
    public Response handle(AuthleteApi api, Options options)
    {
        return handle(api, new CredentialNonceRequest(), options);
    }


    /**
     * Handle a request to the nonce endpoint. This method is an alias of
     * {@link #handle(AuthleteApi, CredentialNonceRequest, Options)
     * handle}{@code (api, request, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param request
     *         The request parameters for Authlete's
     *         {@code /api/<service-id>/vci/nonce} API.
     *
     * @return
     *         A response that should be returned from the nonce endpoint.
     */
    public Response handle(AuthleteApi api, CredentialNonceRequest request)
    {
        return handle(api, request, null);
    }


    /**
     * Handle a request to the nonce endpoint.
     *
     * <p>
     * This method internally creates a {@link CredentialNonceRequestHandler}
     * instance and calls its {@link CredentialNonceRequestHandler#handle(CredentialNonceRequest,
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
     *         {@code /api/<service-id>/vci/nonce} API.
     *
     * @param options
     *         The request options for the
     *         {@code /api/<service-id>/vci/nonce} API.
     *
     * @return
     *         A response that should be returned from the nonce endpoint.
     */
    public Response handle(
            AuthleteApi api, CredentialNonceRequest request, Options options)
    {
        try
        {
            // Create a handler.
            CredentialNonceRequestHandler handler =
                    new CredentialNonceRequestHandler(api);

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
