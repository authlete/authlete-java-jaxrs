/*
 * Copyright (C) 2022 Authlete, Inc.
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
import com.authlete.common.dto.FederationRegistrationRequest;


/**
 * A base class for the federation registration endpoint of <a href=
 * "https://openid.net/specs/openid-connect-federation-1_0.html">OpenID Connect
 * Federation 1&#x002E;0</a>.
 *
 * <p>
 * An OpenID Provider that supports the "explicit" client registration defined
 * in <a href="https://openid.net/specs/openid-connect-federation-1_0.html"
 * >OpenID Connect Federation 1.0</a> is supposed to provide a federation
 * registration endpoint that accepts explicit client registration requests.
 * </p>
 *
 * <p>
 * The endpoint accepts {@code POST} requests whose {@code Content-Type}
 * is either of the following.
 * </p>
 *
 * <ol>
 *   <li>{@code application/entity-statement+jwt}
 *   <li>{@code application/trust-chain+json}
 * </ol>
 *
 * <p>
 * When the {@code Content-Type} of a request is
 * {@code application/entity-statement+jwt}, the content of the request is
 * the entity configuration of a relying party that is to be registered.
 * </p>
 *
 * <p>
 * On the other hand, when the {@code Content-Type} of a request is
 * {@code application/trust-chain+json}, the content of the request is a
 * JSON array that contains entity statements in JWT format. The sequence
 * of the entity statements composes the trust chain of a relying party
 * that is to be registered.
 * </p>
 *
 * <p>
 * On successful registration, the endpoint should return a kind of entity
 * statement (JWT) with the HTTP status code {@code 200 OK} and the content
 * type {@code application/jose}.
 * </p>
 *
 * <p>
 * The discovery document (<a href=
 * "https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect
 * Discovery 1.0</a>) should include the {@code federation_registration_endpoint}
 * server metadata that denotes the URL of the federation registration endpoint.
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-federation-1_0.html"
 *      >OpenID Connect Federation 1.0</a>
 *
 * @since 2.53
 * @since Authlete 2.3
 */
public class BaseFederationRegistrationEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the federation registration endpoint.
     *
     * <p>
     * This method internally creates a {@link FederationRegistrationRequestHandler}
     * instance and calls its {@link
     * FederationRegistrationRequestHandler#handle(FederationRegistrationRequest)
     * handle}<code>({@link FederationRegistrationRequest})</code> method.
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
     *         A response that should be returned from the federation
     *         registration endpoint.
     */
    public Response handle(AuthleteApi api, FederationRegistrationRequest request)
    {
        try
        {
            // Create a handler.
            FederationRegistrationRequestHandler handler =
                    new FederationRegistrationRequestHandler(api);

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
}
