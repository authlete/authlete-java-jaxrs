/*
 * Copyright (C) 2015-2020 Authlete, Inc.
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
import java.util.Arrays;
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
 * In an implementation of token endpoint, call {@link #handle(MultivaluedMap, String)}
 * or {@link #handle(MultivaluedMap, String, String[], String)} method and use the response
 * as the response from the endpoint to the client application. {@code handle()}
 * method calls Authlete's {@code /api/auth/token} API, receives a response from
 * the API, and dispatches processing according to the {@code action} parameter
 * in the response.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class TokenRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the {@link TokenRequestHandler#handle(Params)}
     * method.
     *
     * @since 2.27
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private MultivaluedMap<String, String> parameters;
        private String authorization;
        private String[] clientCertificatePath;
        private String dpop;
        private String htm;
        private String htu;


        /**
         * Get the request parameters of the token request.
         *
         * @return
         *         The request parameters of the token request.
         */
        public MultivaluedMap<String, String> getParameters()
        {
            return parameters;
        }


        /**
         * Set the request parameters of the token request.
         *
         * @param parameters
         *         The request parameters of the token request.
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
         * Get the value of the {@code Authorization} header in the token
         * request. A pair of client ID and client secret is embedded there
         * when the client authentication method is {@code client_secret_basic}.
         *
         * @return
         *         The value of the {@code Authorization} header.
         */
        public String getAuthorization()
        {
            return authorization;
        }


        /**
         * Set the value of the {@code Authorization} header in the token
         * request. A pair of client ID and client secret is embedded there
         * when the client authentication method is {@code client_secret_basic}.
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
         *      >RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
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
         *      >RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
         */
        public Params setClientCertificatePath(String[] path)
        {
            this.clientCertificatePath = path;

            return this;
        }


        /**
         * Get the DPoP proof JWT (the value of the {@code DPoP} HTTP header).
         *
         * <p>
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @return
         *         The DPoP proof JWT.
         */
        public String getDpop()
        {
            return dpop;
        }


        /**
         * Set the DPoP proof JWT (the value of the {@code DPoP} HTTP header).
         *
         * <p>
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param dpop
         *         The DPoP proof JWT.
         *
         * @return
         *         {@code this} object.
         */
        public Params setDpop(String dpop)
        {
            this.dpop = dpop;

            return this;
        }


        /**
         * Get the HTTP method of the token request.
         *
         * @return
         *         The HTTP method of the token request.
         */
        public String getHtm()
        {
            return htm;
        }


        /**
         * Set the HTTP method of the token request.
         *
         * <p>
         * The value should be {@code "POST"} unless new specifications
         * allowing other HTTP methods at the token endpoint are developed.
         * If this parameter is omitted, {@code "POST"} is used as the
         * default value.
         * </p>
         *
         * <p>
         * The value passed here will be used to validate the DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htm
         *         The HTTP method of the token request.
         *
         * @return
         *         {@code this} object.
         */
        public Params setHtm(String htm)
        {
            this.htm = htm;

            return this;
        }


        /**
         * Get the URL of the token endpoint.
         *
         * @return
         *         The URL of the token endpoint.
         */
        public String getHtu()
        {
            return htu;
        }


        /**
         * Set the URL of the token endpoint.
         *
         * <p>
         * If this parameter is omitted, the {@code tokenEndpoint} property
         * of {@link Service} will be used as the default value.
         * </p>
         *
         * <p>
         * The value passed here will be used to validate the DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htu
         *         The URL of the token endpoint.
         *
         * @return
         *         {@code this} object.
         */
        public Params setHtu(String htu)
        {
            this.htu = htu;

            return this;
        }
    }


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
     * Handle a token request.
     *
     * This method is an alias of the {@link #handle(Params)} method.
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
    public Response handle(
            MultivaluedMap<String, String> parameters, String authorization) throws WebApplicationException
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                ;

        return handle(params);
    }


    /**
     * Handle a token request.
     *
     * This method is an alias of the {@link #handle(Params)} method.
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
     * @param clientCertificatePath
     *         The path of the client's certificate, each in PEM format. The first
     *         item in the array is the client's certificate itself. May be {@code null} if
     *         the client did not send a certificate or path.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.8
     */
    public Response handle(
            MultivaluedMap<String, String> parameters, String authorization,
            String[] clientCertificatePath) throws WebApplicationException
    {
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(params);
    }


    /**
     * Handle a token request.
     *
     * @param params
     *         Parameters needed to handle the token request.
     *         Must not be {@code null}.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.27
     */
    public Response handle(Params params) throws WebApplicationException
    {
        // Convert the value of Authorization header (credentials of
        // the client application), if any, into BasicCredentials.
        BasicCredentials credentials = BasicCredentials.parse(params.getAuthorization());

        // The credentials of the client application extracted from
        // 'Authorization' header. These may be null.
        String clientId     = credentials == null ? null : credentials.getUserId();
        String clientSecret = credentials == null ? null : credentials.getPassword();

        try
        {
            // Process the given parameters.
            return process(
                    params.getParameters(),
                    clientId,
                    clientSecret,
                    params.getClientCertificatePath(),
                    params.getDpop(),
                    params.getHtm(),
                    params.getHtu()
            );
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
    private Response process(
            MultivaluedMap<String, String> parameters, String clientId,
            String clientSecret, String[] clientCertificatePath,
            String dpop, String htm, String htu)
    {
        // Extra properties to associate with an access token.
        Property[] properties = mSpi.getProperties();

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

        // Call Authlete's /api/auth/token API.
        TokenResponse response = getApiCaller().callToken(
                parameters, clientId, clientSecret, properties,
                clientCertificate, clientCertificatePath, dpop, htm, htu);

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
