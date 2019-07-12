/*
 * Copyright (C) 2019 Authlete, Inc.
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


import java.util.Arrays;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.DeviceAuthorizationResponse;
import com.authlete.common.dto.DeviceAuthorizationResponse.Action;
import com.authlete.common.web.BasicCredentials;


/**
 * Handler for device authorization requests in OAuth 2.0 Device Authorization
 * Grant (Device Flow).
 *
 * <p>
 * In an implementation of device authorization endpoint, call {@link #handle(MultivaluedMap, String, String[])
 * handle()} method and use the response as the response from the endpoint to the client
 * application. {@code handle()} method calls Authlete's {@code /api/device/authorization}
 * API, receives a response from the API, and dispatches processing according to
 * the {@code action} parameter in the response.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public class DeviceAuthorizationRequestHandler extends BaseHandler
{
    /**
     * The value for {@code WWW-Authenticate} header on 401 Unauthorized.
     */
    private static final String CHALLENGE = "Basic realm=\"device/authorization\"";


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link DeviceAuthorizationRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public DeviceAuthorizationRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handler for device authorization requests in OAuth 2.0 Device Authorization
     * Grant (Device Flow).
     *
     * @param parameters
     *         Request parameters of a device authorization request.
     *
     * @param authorization
     *         The value of {@code Authorization} header in the device authorization
     *         request. A client application may embed its pair of client ID and
     *         client secret in a device authorization request using <a href=
     *         "https://tools.ietf.org/html/rfc2617#section-2">Basic
     *         Authentication</a>.
     *
     * @param clientCertificatePath
     *         The path of the client's certificate, each in PEM format. The first
     *         item in the array is the client's certificate itself. May be {@code null}
     *         if the client did not send a certificate or path.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(
            MultivaluedMap<String, String> parameters, String authorization,
            String[] clientCertificatePath) throws WebApplicationException
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
            return process(parameters, clientId, clientSecret, clientCertificatePath);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in DeviceAuthorizationRequestHandler", t);
        }
    }


    /**
     * Process the parameters of the token request.
     */
    private Response process(
            MultivaluedMap<String, String> parameters, String clientId,
            String clientSecret, String[] clientCertificatePath)
    {
        // TODO: Duplicate code.
        String clientCertificate = null;
        if (clientCertificatePath != null && clientCertificatePath.length > 0)
        {
            // The first one is the client's certificate.
            clientCertificate = clientCertificatePath[0];

            // if we have more in the path, pass them along separately without the first one
            if (clientCertificatePath.length > 1)
            {
                clientCertificatePath = Arrays.copyOfRange(
                        clientCertificatePath, 1, clientCertificatePath.length);
            }
        }

        // Call Authlete's /api/device/authorization API.
        DeviceAuthorizationResponse response = getApiCaller().callDeviceAuthorization(
                parameters, clientId, clientSecret, clientCertificate, clientCertificatePath);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case UNAUTHORIZED:
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
                throw getApiCaller().unknownAction("/api/device/authorization", action);
        }
    }
}
