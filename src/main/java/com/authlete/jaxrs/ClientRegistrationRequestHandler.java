/*
 * Copyright (C) 2019-2021 Authlete, Inc.
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
import com.authlete.common.dto.ClientRegistrationResponse;
import com.authlete.common.dto.ClientRegistrationResponse.Action;
import com.authlete.common.web.BearerToken;


/**
 * Handler for requests to the dynamic client registration and dynamic
 * registration management endpoints.
 *
 * <p>
 * In an implementation of client registration endpoint, call
 * {@link #handleRegister(String, String)} method and use the response as
 * the response from the endpoint to the client application. The
 * {@code handleRegister()} method calls Authlete's {@code /api/client/registration} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * <p>
 * In an implementation of client registration management endpoint's GET functionality
 * call {@link #handleGet(String, String)} method and use the response as
 * the response from the endpoint to the client application. The
 * {@code handleGet()} method calls Authlete's {@code /api/client/registration/get} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * <p>
 * In an implementation of client registration management endpoint's PUT functionality
 * call {@link #handleUpdate(String, String, String)} method and use the response as
 * the response from the endpoint to the client application. The
 * {@code handleUpdate()} method calls Authlete's {@code /api/client/registration/update} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * <p>
 * In an implementation of client registration management endpoint's DELETE functionality
 * call {@link #handleDelete(String, String)} method and use the response as
 * the response from the endpoint to the client application. The
 * {@code handleDelete()} method calls Authlete's {@code /api/client/registration/delete} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/rfc7591">RFC 7591</a>
 *
 * @see <a href="https://tools.ietf.org/html/rfc7592">RFC 7592</a>
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html"
 *      >OpenID Connect Dynamic Client Registration</a>
 *
 * @since 2.17
 */
public class ClientRegistrationRequestHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public ClientRegistrationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a dynamic client registration request.
     *
     * @param json
     *         The serialized JSON body of the client registration request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the token request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @throws WebApplicationException
     *          An error occurred.
     */
    public Response handleRegister(String json, String authorization)
    {
        String initialAccessToken = BearerToken.parse(authorization);

        try
        {
            ClientRegistrationResponse response = getApiCaller().callClientRegistration(
                    json, initialAccessToken);
            return process(response);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw unexpected("Unexpected error in ClientRegistrationRequestHandler", t);
        }
    }


    /**
     * Handle a dynamic client management GET request.
     *
     * @param clientId
     *         The client ID as determined by the incoming request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @throws WebApplicationException
     *          An error occurred.
     */
    public Response handleGet(String clientId, String authorization)
    {
        String registrationAccessToken = BearerToken.parse(authorization);

        try
        {
            ClientRegistrationResponse response = getApiCaller().callClientRegistrationGet(
                    clientId, registrationAccessToken);
            return process(response);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw unexpected("Unexpected error in ClientRegistrationRequestHandler", t);
        }
    }


    /**
     * Handle a dynamic client management PUT request.
     *
     * @param clientId
     *         The client ID as determined by the incoming request.
     *
     * @param json
     *         The serialized JSON body of the client update request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @throws WebApplicationException
     *          An error occurred.
     */
    public Response handleUpdate(String clientId, String json, String authorization)
    {
        String registrationAccessToken = BearerToken.parse(authorization);

        try
        {
            ClientRegistrationResponse response = getApiCaller().callClientRegistrationUpdate(
                    clientId, json, registrationAccessToken);
            return process(response);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw unexpected("Unexpected error in ClientRegistrationRequestHandler", t);
        }
    }


    /**
     * Handle a dynamic client management DELETE request.
     *
     * @param clientId
     *         The client ID as determined by the incoming request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @throws WebApplicationException
     *          An error occurred.
     */
    public Response handleDelete(String clientId, String authorization)
    {
        String registrationAccessToken = BearerToken.parse(authorization);

        try
        {
            ClientRegistrationResponse response = getApiCaller().callClientRegistrationDelete(
                    clientId, registrationAccessToken);
            return process(response);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw unexpected("Unexpected error in ClientRegistrationRequestHandler", t);
        }
    }


    /**
     * Process the Action in the response.
     *
     * @param response
     *         The Authlete API response to process.
     *
     * @return
     *         The response to return to the client.
     */
    private Response process(ClientRegistrationResponse response)
    {
        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            case UNAUTHORIZED:
                // 401 Unauthorized
                return ResponseUtil.unauthorized(content, null);

            case CREATED:
                // 201 Created
                return ResponseUtil.created(content);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case OK:
                // 200 OK
                return ResponseUtil.ok(content);

            case DELETED:
                // 204 no content
                return ResponseUtil.noContent();

            case UPDATED:
                // 200 OK
                return ResponseUtil.ok(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/client/registration/*", action);
        }
    }
}
