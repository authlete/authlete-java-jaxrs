/*
 * Copyright (C) 2016-2025 Authlete, Inc.
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
import com.authlete.common.dto.ServiceConfigurationRequest;


/**
 * Handler for requests to an OpenID Provider configuration endpoint.
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
 * In an implementation of configuration endpoint, call {@link #handle()} method
 * and use the response as the response from the endpoint to the client application.
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
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class ConfigurationRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public ConfigurationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method is an alias of {@link #handle(boolean) handle}{@code (true)}.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle() throws WebApplicationException
    {
        return handle(true);
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method is an alias of {@link #handle(boolean, Options) handle}{@code (true, options)}.
     *
     * @param options
     *         The request options to the Authlete API.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.82
     */
    public Response handle(Options options) throws WebApplicationException
    {
        return handle(true, options);
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method is an alias of {@link #handle(boolean, Options) handle}{@code (pretty, null)}.
     *
     * @param pretty
     *         {@code true} to return the output JSON in pretty format.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(boolean pretty) throws WebApplicationException
    {
        return handle(pretty, null);
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method internally calls Authlete's {@code /api/service/configuration}
     * API.
     *
     * @param pretty
     *         {@code true} to return the output JSON in pretty format.
     *
     * @param options
     *         The request options to the Authlete API.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.82
     */
    public Response handle(boolean pretty, Options options) throws WebApplicationException
    {
        try
        {
            // Call Authlete's /api/service/configuration API.
            // The API returns a JSON that complies with
            // OpenID Connect Discovery 1.0.
            String json = getApiCaller().callServiceConfiguration(pretty, options);

            // Response as "application/json;charset=UTF-8" with 200 OK.
            return ResponseUtil.ok(json);
        }
        catch (WebApplicationException e)
        {
            // The API call raised an exception.
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in ConfigurationRequestHandler", t);
        }
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method is an alias of {@link
     * #handle(ServiceConfigurationRequest, Options) handle}{@code (request, null)}.
     *
     * @param request
     *         The request parameters to the Authlete API.
     *
     * @return
     *         A response that should be returned from the discovery endpoint.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.50
     */
    public Response handle(ServiceConfigurationRequest request) throws WebApplicationException
    {
        return handle(request, null);
    }


    /**
     * Handle a request to an OpenID Provider configuration endpoint. This
     * method internally calls Authlete's {@code /api/service/configuration}
     * API.
     *
     * @param request
     *         The request parameters to the Authlete API.
     *
     * @param options
     *         The request options to the Authlete API.
     *
     * @return
     *         A response that should be returned from the discovery endpoint.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.82
     */
    public Response handle(
            ServiceConfigurationRequest request, Options options) throws WebApplicationException
    {
        try
        {
            // Call Authlete's /api/service/configuration API.
            // The API returns a JSON that complies with
            // OpenID Connect Discovery 1.0.
            String json = getApiCaller().callServiceConfiguration(request, options);

            // Response as "application/json;charset=UTF-8" with 200 OK.
            return ResponseUtil.ok(json);
        }
        catch (WebApplicationException e)
        {
            // The API call raised an exception.
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in ConfigurationRequestHandler", t);
        }
    }
}
