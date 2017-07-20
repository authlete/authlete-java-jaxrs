/*
 * Copyright (C) 2017 Authlete, Inc.
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
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.StandardIntrospectionResponse.Action;


/**
 * Handler for token introspection requests
 * (<a href="https://tools.ietf.org/html/rfc7662">RFC 7662</a>).
 *
 * <p>
 * In an implementation of introspection endpoint, call {@link
 * #handle(MultivaluedMap) handle()} method and use the response
 * as the response from the endpoint to the client application.
 * {@code handle()} method calls Authlete's {@code
 * /api/auth/introspection/standard} API, receives a response
 * from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @since 2.2
 *
 * @author Takahiko Kawasaki
 */
public class IntrospectionRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public IntrospectionRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle an introspection request (<a href="https://tools.ietf.org/html/rfc7662"
     * >RFC 7662</a>).
     *
     * @param parameters
     *         Request parameters of a token introspection request.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(MultivaluedMap<String, String> parameters) throws WebApplicationException
    {
        try
        {
            // Process the given parameters.
            return process(parameters);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in IntrospectionRequestHandler", t);
        }
    }


    /**
     * Process the parameters of the introspection request.
     */
    private Response process(MultivaluedMap<String, String> parameters)
    {
        // Call Authlete's /api/auth/introspection/standard API.
        StandardIntrospectionResponse response = getApiCaller().callStandardIntrospection(parameters);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
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
                throw getApiCaller().unknownAction("/api/auth/introspection/standard", action);
        }
    }
}
