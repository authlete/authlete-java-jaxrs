/*
 * Copyright (C) 2015-2024 Authlete, Inc.
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
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.RevocationResponse.Action;


/**
 * Handler for token revocation requests
 * (<a href="https://www.rfc-editor.org/rfc/rfc7009.html">RFC 7009</a>).
 *
 * <p>
 * In an implementation of revocation endpoint, call {@link #handle(Params)}
 * method and use the response as the response from the endpoint to the client
 * application. {@code handle()} method calls Authlete's {@code /auth/revocation} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @since 1.1
 *
 * @author Takahiko Kawasaki
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7009.html"
 *      >RFC 7009: OAuth 2.0 Token Revocation</a>
 */
public class RevocationRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the {@link RevocationRequestHandler#handle(Params)}
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
         * Get the request parameters of the revocation request.
         *
         * @return
         *         The request parameters.
         */
        public MultivaluedMap<String, String> getParameters()
        {
            return parameters;
        }


        /**
         * Set the request parameters of the revocation request.
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
         * Get the value of the {@code Authorization} header in the revocation
         * request. A pair of client ID and client secret is embedded there when
         * the client authentication method is {@code client_secret_basic}.
         *
         * @return
         *         The value of the {@code Authorization} header.
         */
        public String getAuthorization()
        {
            return authorization;
        }


        /**
         * Set the value of the {@code Authorization} header in the revocation
         * request. A pair of client ID and client secret is embedded there when
         * the client authentication method is {@code client_secret_basic}.
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
     * Handle a token revocation request (<a href="https://www.rfc-editor.org/rfc/rfc7009.html"
     * >RFC 7009</a>).
     *
     * @param parameters
     *         Request parameters of a token revocation request.
     *
     * @param authorization
     *         The value of {@code Authorization} header in the token revocation
     *         request. A client application may embed its pair of client ID and
     *         client secret in a token revocation request using <a href=
     *         "https://www.rfc-editor.org/rfc/rfc2617.html#section-2">Basic
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
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                ;

        return handle(params);
    }


    /**
     * Handle a token revocation request.
     *
     * @param params
     *         Parameters for Authlete's {@code /auth/revocation} API.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.79
     */
    public Response handle(Params params) throws WebApplicationException
    {
        // The credential of the client application extracted from the
        // Authorization header. If available, the first element is the
        // client ID and the second element is the client secret.
        String[] credential = HandlerUtility
                .extractClientCredentialFromAuthorization(params.getAuthorization());

        try
        {
            // Process the given parameters.
            return process(params, credential[0], credential[1]);
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
    private Response process(Params params, String clientId, String clientSecret)
    {
        // The client certificate.
        String clientCertificate = HandlerUtility
                .extractClientCertificate(params.getClientCertificatePath());

        // The second and subsequent elements in the client certificate path.
        String[] clientCertificatePath = HandlerUtility
                .extractSubsequenceFromClientCertificatePath(params.getClientCertificatePath());

        // Call Authlete's /api/auth/revocation API.
        RevocationResponse response = getApiCaller().callRevocation(
                params.getParameters(), clientId, clientSecret,
                clientCertificate, clientCertificatePath,
                params.getClientAttestation(), params.getClientAttestationPop());

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
                return ResponseUtil.javaScript(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/revocation", action);
        }
    }
}
