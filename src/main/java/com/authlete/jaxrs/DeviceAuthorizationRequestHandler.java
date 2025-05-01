/*
 * Copyright (C) 2019-2024 Authlete, Inc.
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


import java.io.Serializable;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.Options;
import com.authlete.common.dto.DeviceAuthorizationResponse;
import com.authlete.common.dto.DeviceAuthorizationResponse.Action;


/**
 * Handler for device authorization requests in OAuth 2&#x2E;0
 * Device Authorization Grant (Device Flow).
 *
 * <p>
 * In an implementation of device authorization endpoint, call
 * {@link #handle(Params)} method and use the response as the
 * response from the endpoint to the client application.
 * {@code handle()} method calls Authlete's {@code /device/authorization}
 * API, receives a response from the API, and dispatches processing
 * according to the {@code action} parameter in the response.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8628.html"
 *      >RFC 8628: OAuth 2.0 Device Authorization Grant</a>
 */
public class DeviceAuthorizationRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the
     * {@link DeviceAuthorizationRequestHandler#handle(Params)}
     * method.
     *
     * @since 2.79
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private MultivaluedMap<String, String> parameters;
        private String authorization;
        private String[] clientCertificatePath;
        private String clientAttestation;
        private String clientAttestationPop;


        /**
         * Get the request parameters of the device authorization request.
         *
         * @return
         *         The request parameters.
         */
        public MultivaluedMap<String, String> getParameters()
        {
            return parameters;
        }


        /**
         * Set the request parameters of the device authorization request.
         *
         * @param parameters
         *         The request parameters.
         *
         * @return
         *         {@code this} object.
         */
        public Params setParameters(MultivaluedMap<String, String> parameters)
        {
            this.parameters = parameters;

            return this;
        }


        /**
         * Get the value of the {@code Authorization} header in the device
         * authorization request. A pair of client ID and client secret is
         * embedded there when the client authentication method is
         * {@code client_secret_basic}.
         *
         * @return
         *         The value of the {@code Authorization} header.
         */
        public String getAuthorization()
        {
            return authorization;
        }


        /**
         * Set the value of the {@code Authorization} header in the device
         * authorization request. A pair of client ID and client secret is
         * embedded there when the client authentication method is
         * {@code client_secret_basic}.
         *
         * @param authorization
         *         The value of the {@code Authorization} header.
         *
         * @return
         *         {@code this} object.
         */
        public Params setAuthorization(String authorization)
        {
            this.authorization = authorization;

            return this;
        }


        /**
         * Get the path of the client's certificate, each in PEM format.
         * The first item in the array is the client's certificate itself.
         *
         * @return
         *         The path of the client's certificate.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html"
         *      >RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and
         *       Certificate-Bound Access Tokens</a>
         */
        public String[] getClientCertificatePath()
        {
            return clientCertificatePath;
        }


        /**
         * Set the path of the client's certificate, each in PEM format.
         * The first item in the array is the client's certificate itself.
         *
         * @param path
         *         The path of the client's certificate.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html"
         *      >RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and
         *       Certificate-Bound Access Tokens</a>
         */
        public Params setClientCertificatePath(String[] path)
        {
            this.clientCertificatePath = path;

            return this;
        }


        /**
         * Get the value of the {@code OAuth-Client-Attestation} HTTP header.
         *
         * @return
         *         The value of the {@code OAuth-Client-Attestation} HTTP header.
         *
         * @since Authlete 3.0
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/"
         *      >OAuth 2.0 Attestation-Based Client Authentication</a>
         */
        public String getClientAttestation()
        {
            return clientAttestation;
        }


        /**
         * Set the value of the {@code OAuth-Client-Attestation} HTTP header.
         *
         * @param jwt
         *         The value of the {@code OAuth-Client-Attestation} HTTP header.
         *
         * @return
         *         {@code this} object.
         *
         * @since Authlete 3.0
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/"
         *      >OAuth 2.0 Attestation-Based Client Authentication</a>
         */
        public Params setClientAttestation(String jwt)
        {
            this.clientAttestation = jwt;

            return this;
        }


        /**
         * Get the value of the {@code OAuth-Client-Attestation-PoP} HTTP header.
         *
         * @return
         *         The value of the {@code OAuth-Client-Attestation-PoP} HTTP header.
         *
         * @since Authlete 3.0
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/"
         *      >OAuth 2.0 Attestation-Based Client Authentication</a>
         */
        public String getClientAttestationPop()
        {
            return clientAttestationPop;
        }


        /**
         * Set the value of the {@code OAuth-Client-Attestation-PoP} HTTP header.
         *
         * @param jwt
         *         The value of the {@code OAuth-Client-Attestation-PoP} HTTP header.
         *
         * @return
         *         {@code this} object.
         *
         * @since Authlete 3.0
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/"
         *      >OAuth 2.0 Attestation-Based Client Authentication</a>
         */
        public Params setClientAttestationPop(String jwt)
        {
            this.clientAttestationPop = jwt;

            return this;
        }
    }


    /**
     * The value for {@code WWW-Authenticate} header on 401 Unauthorized.
     */
    private static final String CHALLENGE = "Basic realm=\"device/authorization\"";


    /**
     * Constructor with an implementation of the {@link AuthleteApi} interface.
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
     *         "https://www.rfc-editor.org/rfc/rfc2617.html#section-2">Basic
     *         Authentication</a>.
     *
     * @param clientCertificatePath
     *         The path of the client's certificate, each in PEM format. The first
     *         item in the array is the client's certificate itself. May be {@code null}
     *         if the client did not send a certificate or path.
     *
     * @param options
     *         The request options for the device authorization request.
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
            String[] clientCertificatePath, Options options) throws WebApplicationException
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(params, options);
    }


    /**
     * Handle a device authorization request.
     *
     * @param params
     *         Parameters for Authlete's {@code /device/authorization} API.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @since 2.79
     */
    public Response handle(Params params)
    {
        return handle(params, null);
    }


    /**
     * Handle a device authorization request.
     *
     * @param params
     *         The request parameters for Authlete's {@code /device/authorization} API.
     *
     * @param options
     *         The request options for Authlete's {@code /device/authorization} API.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @since 2.79
     */
    public Response handle(Params params, Options options)
    {
        // The credential of the client application extracted from the
        // Authorization header. If available, the first element is the
        // client ID and the second element is the client secret.
        String[] credential = HandlerUtility
                .extractClientCredentialFromAuthorization(params.getAuthorization());

        try
        {
            // Process the given parameters.
            return process(params, credential[0], credential[1], options);
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
            Params params, String clientId, String clientSecret, Options options)
    {
        // The client certificate.
        String clientCertificate = HandlerUtility
                .extractClientCertificate(params.getClientCertificatePath());

        // The second and subsequent elements in the client certificate path.
        String[] clientCertificatePath = HandlerUtility
                .extractSubsequenceFromClientCertificatePath(params.getClientCertificatePath());

        // Call Authlete's /api/device/authorization API.
        DeviceAuthorizationResponse response = getApiCaller().callDeviceAuthorization(
                params.getParameters(), clientId, clientSecret,
                clientCertificate, clientCertificatePath,
                params.getClientAttestation(), params.getClientAttestationPop(),
                options);

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
