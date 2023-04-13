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
import com.authlete.common.dto.CredentialIssuerMetadataRequest;


/**
 * A base class for the credential issuer metadata endpoint
 * ({@code /.well-known/openid-credential-issuer}) defined in <a href=
 * "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 * >OpenID for Verifiable Credential Issuance</a>.
 *
 * <p>
 * A credential issuer that supports <a href=
 * "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 * >OpenID for Verifiable Credential Issuance</a> must provide an endpoint that
 * returns its <b>credential issuer metadata</b> in the JSON format. The URL of
 * the endpoint is defined as follows:
 * </p>
 *
 * <blockquote>
 * Credential Issuer Identifier + {@code /.well-known/openid-credential-issuer}
 * </blockquote>
 *
 * <p>
 * <b>Credential Issuer Identifier</b> is a URL that identifies a credential
 * issuer.
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"
 *      >OpenID for Verifiable Credential Issuance</a>
 *
 * @since 2.57
 * @since Authlete 3.0
 */
public class BaseCredentialIssuerMetadataEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the credential issuer metadata endpoint.
     *
     * <p>
     * This method internally creates a {@link CredentialIssuerMetadataRequestHandler}
     * instance and calls its {@link
     * CredentialIssuerMetadataRequestHandler#handle(CredentialIssuerMetadataRequest)
     * handle}<code>({@link CredentialIssuerMetadataRequest})</code> method.
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
     *         A response that should be returned from the credential issuer
     *         metadata endpoint.
     */
    public Response handle(AuthleteApi api, CredentialIssuerMetadataRequest request)
    {
        try
        {
            // Create a handler.
            CredentialIssuerMetadataRequestHandler handler =
                    new CredentialIssuerMetadataRequestHandler(api);

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
     * Handle a request to the credential issuer metadata endpoint.
     *
     * <p>
     * This method is an alias of {@link
     * #handle(AuthleteApi, CredentialIssuerMetadataRequest)
     * handle}{@code (api, new CredentialIssuerMetadataRequest())}
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the credential issuer
     *         metadata endpoint.
     */
    public Response handle(AuthleteApi api)
    {
        return handle(api, new CredentialIssuerMetadataRequest());
    }
}
