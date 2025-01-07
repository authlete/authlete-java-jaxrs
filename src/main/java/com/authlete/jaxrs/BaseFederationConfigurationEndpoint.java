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


/**
 * A base class for the entity configuration endpoint of <a href=
 * "https://openid.net/specs/openid-connect-federation-1_0.html">OpenID Connect
 * Federation 1&#x002E;0</a>.
 *
 * <p>
 * An OpenID Provider that supports <a href=
 * "https://openid.net/specs/openid-connect-federation-1_0.html">OpenID Connect
 * Federation 1.0</a> must provide an endpoint that returns its <b>entity
 * configuration</b> in the JWT format. The URI of the endpoint is defined
 * as follows:
 * </p>
 *
 * <ol>
 * <li>Entity ID + {@code /.well-known/openid-federation}
 * <li>Host component of Entity ID + {@code /.well-known/openid-federation}
 *     + Path component of Entity ID (The same rule in <a href=
 *     "https://www.rfc-editor.org/rfc/rfc8414.html">RFC 8414</a>)
 * </ol>
 *
 * <p>
 * <b>Entity ID</b> is a URL that identifies an OpenID Provider (and other
 * entities including Relying Parties, Trust Anchors and Intermediate
 * Authorities) in the context of OpenID Connect Federation 1.0.
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-federation-1_0.html"
 *      >OpenID Connect Federation 1.0</a>
 *
 * @since 2.49
 * @since Authlete 2.3
 */
public class BaseFederationConfigurationEndpoint extends BaseEndpoint
{
    /**
     * Handle a request to the entity configuration endpoint. This method is an alias
     * of the {@link #handle(AuthleteApi, FederationConfigurationRequest)} method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     */
    public Response handle(AuthleteApi api)
    {
        return handle(api, new FederationConfigurationRequest());
    }


    /**
     * Handle a request to the entity configuration endpoint. This method is an
     * alias of the {@link #handle(AuthleteApi, FederationConfigurationRequest, Options)}
     * method.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param options
     *         The request options for the {@code /api/federation/configuration} API.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     *
     * @since 2.82
     */
    public Response handle(AuthleteApi api, Options options)
    {
        return handle(api, new FederationConfigurationRequest(), null);
    }


    /**
     * Handle a request to the entity configuration endpoint. This method is an
     * alias of {@link #handle(AuthleteApi, FederationConfigurationRequest, Options)
     * handle}{@code (api, request, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param request
     *         The request parameters for Authlete's {@code /api/federation/configuration} API.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     */
    public Response handle(AuthleteApi api, FederationConfigurationRequest request)
    {
        return handle(api, request, null);
    }


    /**
     * Handle a request to the entity configuration endpoint.
     *
     * <p>
     * This method internally creates a {@link FederationConfigurationRequestHandler}
     * instance and calls its {@link
     * FederationConfigurationRequestHandler#handle(FederationConfigurationRequest, Options) handle()}
     * method. Then, this method uses the value returned from the handler's method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When the handler's method raises a {@link WebApplicationException}, this
     * method calls {@link #onError(WebApplicationException) onError()} method with the exception.
     * The default implementation of {@code onError()} does nothing. You can override the
     * method as necessary. After calling {@code onError()} method, this method
     * calls {@code getResponse()} method of the exception and uses the returned
     * value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param request
     *         The request parameters for Authlete's {@code /api/federation/configuration} API.
     *
     * @param options
     *         The request options for the {@code /api/federation/configuration} API.
     *
     * @return
     *         A response that should be returned from the entity configuration
     *         endpoint.
     *
     * @since 2.82
     */
    public Response handle(
            AuthleteApi api, FederationConfigurationRequest request, Options options)
    {
        try
        {
            // Create a handler.
            FederationConfigurationRequestHandler handler =
                    new FederationConfigurationRequestHandler(api);

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
