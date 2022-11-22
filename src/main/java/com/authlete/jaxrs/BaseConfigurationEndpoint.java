/*
 * Copyright (C) 2016-2022 Authlete, Inc.
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
import com.authlete.common.dto.ServiceConfigurationRequest;


/**
 * A base class for OpenID Provider configuration endpoints.
 *
 * <p>
 * An OpenID Provider that supports <a href=
 * "http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect
 * Discovery 1.0</a> must provide an endpoint that returns its configuration
 * information in a JSON format. Details about the format are described in
 * "<a href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
 * >3. OpenID Provider Metadata</a>" in OpenID Connect Discovery 1.0.
 * </p>
 *
 * <p>
 * Note that the URI of an OpenID Provider configuration endpoint is defined in
 * "<a href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest"
 * >4.1. OpenID Provider Configuration Request</a>" in OpenID Connect Discovery
 * 1.0. In short, the URI must be:
 * </p>
 *
 * <blockquote>
 * Issuer Identifier + {@code /.well-known/openid-configuration}
 * </blockquote>
 *
 * <p>
 * <i>Issuer Identifier</i> is a URL to identify an OpenID Provider. For example,
 * {@code https://example.com}. For details about Issuer Identifier, See <b>{@code issuer}</b>
 * in "<a href="http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata"
 * >3. OpenID Provider Metadata</a>" (OpenID Connect Discovery 1.0) and <b>{@code iss}</b> in
 * "<a href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">2. ID Token</a>"
 * (OpenID Connect Core 1.0).
 * </p>
 *
 * <p>
 * You can change the Issuer Identifier of your service using the management console
 * (<a href="https://www.authlete.com/documents/so_console">Service Owner Console</a>).
 * Note that the default value of Issuer Identifier is not appropriate for commercial
 * use, so you should change it.
 * </p>
 *
 * @see <a href="http://openid.net/specs/openid-connect-discovery-1_0.html"
 *      >OpenID Connect Discovery 1.0</a>
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class BaseConfigurationEndpoint extends BaseEndpoint
{
    /**
     * Handle a request for OpenID Provider configuration.
     *
     * <p>
     * This method internally creates a {@link ConfigurationRequestHandler}
     * instance and calls its {@link ConfigurationRequestHandler#handle()} method.
     * Then, this method uses the value returned from the {@code handle()} method
     * as a response from this method.
     * </p>
     *
     * <p>
     * When {@code ConfigurationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You
     * can override the method as necessary. After calling {@code onError()} method,
     * this method calls {@code getResponse()} method of the exception and uses the
     * returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handle(AuthleteApi api)
    {
        try
        {
            // Create a handler.
            ConfigurationRequestHandler handler = new ConfigurationRequestHandler(api);

            // Delegate the task to the handler.
            return handler.handle();
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
     * Handle a request for OpenID Provider configuration.
     *
     * <p>
     * This method internally creates a {@link ConfigurationRequestHandler}
     * instance and calls its
     * {@link ConfigurationRequestHandler#handle(ServiceConfigurationRequest)
     * handle}{@code (}{@link ServiceConfigurationRequest}{@code )} method.
     * Then, this method uses the value returned from the method as a response
     * from this method.
     * </p>
     *
     * <p>
     * When handler's method raises a {@link WebApplicationException}, this
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
     *         Request parameters for Authlete's {@code /service/configuration} API.
     *
     * @return
     *         A response that should be returned from the discovery endpoint.
     *
     * @since 2.50
     */
    public Response handle(AuthleteApi api, ServiceConfigurationRequest request)
    {
        try
        {
            // Create a handler.
            ConfigurationRequestHandler handler = new ConfigurationRequestHandler(api);

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
