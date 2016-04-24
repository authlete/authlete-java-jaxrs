/*
 * Copyright (C) 2015-2016 Authlete, Inc.
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
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.Property;
import com.authlete.common.dto.TokenFailRequest.Reason;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.dto.TokenResponse.Action;
import com.authlete.common.web.BasicCredentials;
import com.authlete.jaxrs.spi.TokenRequestHandlerSpi;


/**
 * Handler for token requests to a <a href=
 * "https://tools.ietf.org/html/rfc6749#section-3.2">token endpoint</a> of OAuth 2.0
 * (<a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>).
 *
 * <p>
 * In an implementation of token endpoint, call {@link #handle(MultivaluedMap, String)
 * handle()} method and use the response as the response from the endpoint to the client
 * application. {@code handle()} method calls Authlete's {@code /api/auth/token} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class TokenRequestHandler extends BaseHandler
{
    /**
     * The value for {@code WWW-Authenticate} header on 401 Unauthorized.
     */
    private static final String CHALLENGE = "Basic realm=\"token\"";


    /**
     * Implementation of {@link TokenRequestHandlerSpi} interface.
     */
    private final TokenRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link TokenRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link TokenRequestHandlerSpi} interface.
     */
    public TokenRequestHandler(AuthleteApi api, TokenRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle a token request to a <a href="https://tools.ietf.org/html/rfc6749#section-3.2"
     * >token endpoint</a> of OAuth 2.0 (<a href="https://tools.ietf.org/html/rfc6749"
     * >RFC 6749</a>).
     *
     * @param parameters
     *         Request parameters of a token request.
     *
     * @param authorization
     *         The value of {@code Authorization} header in the token request.
     *         A client application may embed its pair of client ID and client
     *         secret in a token request using <a href=
     *         "https://tools.ietf.org/html/rfc2617#section-2">Basic
     *         Authentication</a>.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(MultivaluedMap<String, String> parameters, String authorization) throws WebApplicationException
    {
        // Convert the value of Authorization header (credentials of
        // the client application), if any, into BasicCredentials.
        BasicCredentials credentials = BasicCredentials.parse(authorization);

        // The credentials of the client application extracted from
        // 'Authorization' header. These may be null.
        String clientId     = credentials == null ? null : credentials.getUserId();
        String clientSecret = credentials == null ? null : credentials.getPassword();

        try
        {
            // Process the given parameters.
            return process(parameters, clientId, clientSecret);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in TokenRequestHandler", t);
        }
    }


    /**
     * Process the parameters of the token request.
     */
    private Response process(MultivaluedMap<String, String> parameters, String clientId, String clientSecret)
    {
        // Extra properties to associate with an access token.
        Property[] properties = mSpi.getProperties();

        // Call Authlete's /api/auth/token API.
        TokenResponse response = getApiCaller().callToken(parameters, clientId, clientSecret, properties);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INVALID_CLIENT:
                // 401 Unauthorized
                return ResponseUtil.unauthorized(content, CHALLENGE);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            case PASSWORD:
                // Process the token request whose flow is "Resource Owner Password Credentials".
                return handlePassword(response);

            case OK:
                // 200 OK
                return ResponseUtil.ok(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/token", action);
        }
    }


    /**
     * Process the token request whose flow is "Resource Owner Password Credentials".
     */
    private Response handlePassword(TokenResponse response)
    {
        // The credentials of the resource owner.
        String username = response.getUsername();
        String password = response.getPassword();

        // Validate the credentials.
        String subject = mSpi.authenticateUser(username, password);

        // Extra properties to associate with an access token.
        Property[] properties = mSpi.getProperties();

        // The ticket for Authlete's /api/auth/token/* API.
        String ticket = response.getTicket();

        if (subject != null)
        {
            // Issue an access token and optionally an ID token.
            return getApiCaller().tokenIssue(ticket, subject, properties);
        }
        else
        {
            // The credentials are invalid. An access token is not issued.
            throw getApiCaller().tokenFail(ticket, Reason.INVALID_RESOURCE_OWNER_CREDENTIALS);
        }
    }
}
