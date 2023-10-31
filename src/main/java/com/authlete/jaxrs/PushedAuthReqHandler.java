/*
 * Copyright (C) 2019-2023 Authlete, Inc.
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
import java.util.LinkedHashMap;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.PushedAuthReqResponse;
import com.authlete.common.dto.PushedAuthReqResponse.Action;
import com.authlete.common.web.BasicCredentials;


/**
 * Handler for pushed authorization request endpoint requests.
 *
 * <p>
 * In an implementation of the pushed authorization request endpoint, call
 * {@link #handle(MultivaluedMap, String, String[]) handle()} method and use
 * the response as the response from the endpoint to the client application.
 * The {@code handle()} method calls Authlete's
 * {@code /api/pushed_auth_req} API, receives a response from the API, and
 * dispatches processing according to the {@code action} parameter in the response.
 * </p>
 *
 * @see <a href="https://tools.ietf.org/html/draft-lodderstedt-oauth-par"
 *      >OAuth 2.0 Pushed Authorization Requests</a>
 *
 * @since 2.21
 *
 * @author Justin Richer
 */
public class PushedAuthReqHandler extends BaseHandler
{
    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *            Implementation of {@link AuthleteApi} interface.
     */
    public PushedAuthReqHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle a pushed authorization request.
     *
     * @param parameters
     *            Request parameters of a pushed authorization request.
     *
     * @param authorization
     *            The value of {@code Authorization} header in the pushed
     *            authorization request. A client application may embed its
     *            pair of client ID and client secret in a pushed authorization
     *            request using <a href="https://tools.ietf.org/html/rfc2617#section-2"
     *            >Basic Authentication</a>.
     *
     * @param clientCertificatePath
     *            The path of the client's certificate, each in PEM format.
     *            The first item in the array is the client's certificate itself.
     *            May be {@code null} if the client did not send a certificate or path.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *             An error occurred.
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
            throw unexpected("Unexpected error in PushedAuthReqHandler", t);
        }
    }


    /**
     * Process the parameters of the pushed authorization request.
     */
    private Response process(MultivaluedMap<String, String> parameters, String clientId, String clientSecret, String[] clientCertificatePath)
    {
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

        PushedAuthReqResponse response = getApiCaller().callPushedAuthReq(
                parameters, clientId, clientSecret,
                clientCertificate, clientCertificatePath);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Additional HTTP headers.
        Map<String, Object> headers = prepareHeaders(response);

        // Dispatch according to the action.
        switch (action)
        {
            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content, headers);

            case CREATED:
                // 201 Created
                return ResponseUtil.created(content, headers);

            case FORBIDDEN:
                // 403 forbidden
                return ResponseUtil.forbidden(content, headers);

            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content, headers);

            case PAYLOAD_TOO_LARGE:
                // 413 Too Large
                return ResponseUtil.tooLarge(content, headers);

            case UNAUTHORIZED:
                // 401 Unauthorized
                return ResponseUtil.unauthorized(content, null, headers);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/pushed_auth_req", action);
        }
    }


    private static Map<String, Object> prepareHeaders(PushedAuthReqResponse response)
    {
        Map<String, Object> headers = new LinkedHashMap<>();

        // DPoP-Nonce
        String dpopNonce = response.getDpopNonce();
        if (dpopNonce != null)
        {
            headers.put("DPoP-Nonce", dpopNonce);
        }

        return headers;
    }
}
