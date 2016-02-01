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
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.RevocationResponse.Action;
import com.authlete.common.web.BasicCredentials;


/**
 * Handler for token revocation requests
 * (<a href="https://tools.ietf.org/html/rfc7009">RFC 7009</a>).
 *
 * <p>
 * In an implementation of revocation endpoint, call {@link #handle(MultivaluedMap, String)
 * handle()} method and use the response as the response from the endpoint to the client
 * application. {@code handle()} method calls Authlete's {@code /api/auth/revocation} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 */
public class RevocationRequestHandler extends BaseHandler
{
    /**
     * The value for {@code WWW-Authenticate} header on 401 Unauthorized.
     */
    private static final String CHALLENGE = "Basic realm=\"revocation\"";


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public RevocationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a token revocation request (<a href="https://tools.ietf.org/html/rfc7009"
     * >RFC 7009</a>).
     *
     * @param parameters
     *         Request parameters of a token revocation request.
     *
     * @param authorization
     *         The value of {@code Authorization} header in the token revocation
     *         request. A client application may embed its pair of client ID and
     *         client secret in a token revocation request using <a href=
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
            throw unexpected("Unexpected error in RevocationRequestHandler", t);
        }
    }


    /**
     * Process the parameters of the revocation request.
     */
    private Response process(MultivaluedMap<String, String> parameters, String clientId, String clientSecret)
    {
        // Call Authlete's /api/auth/revocation API.
        RevocationResponse response = getApiCaller().callRevocation(parameters, clientId, clientSecret);

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

            case OK:
                // 200 OK
                return ResponseUtil.ok(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/revocation", action);
        }
    }
}
