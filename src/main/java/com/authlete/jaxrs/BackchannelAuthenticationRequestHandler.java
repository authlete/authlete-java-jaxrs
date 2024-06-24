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
import com.authlete.common.dto.BackchannelAuthenticationFailRequest.Reason;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.types.User;
import com.authlete.common.types.UserIdentificationHintType;
import com.authlete.jaxrs.spi.BackchannelAuthenticationRequestHandlerSpi;


/**
 * Handler for backchannel authentication requests to a backchannel authentication
 * endpoint of CIBA (Client Initiated Backchannel Authentication).
 *
 * <p>
 * In an implementation of the backchannel authentication endpoint, call
 * [@link #handle(Params)} method and use the response as the response
 * from the endpoint to the client application. The {@code handle()}
 * method calls Authlete's {@code /backchannel/authentication} API,
 * receives a response from the API, and dispatches processing according
 * to the {@code action} parameter in the response.
 * </p>
 *
 * @since 2.13
 *
 * @author Hideki Ikeda
 */
public class BackchannelAuthenticationRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the
     * {@link BackchannelAuthenticationRequestHandler#handle(Params)}
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
         * Get the request parameters of the backchannel authentication request.
         *
         * @return
         *         The request parameters.
         */
        public MultivaluedMap<String, String> getParameters()
        {
            return parameters;
        }


        /**
         * Set the request parameters of the backchannel authentication request.
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
         * Get the value of the {@code Authorization} header in the backchannel
         * authentication request. A pair of client ID and client secret is
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
         * Set the value of the {@code Authorization} header in the backchannel
         * authentication request. A pair of client ID and client secret is
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
    private static final String CHALLENGE = "Basic realm=\"backchannel/authentication\"";


    /**
     * Implementation of {@link BackchannelAuthenticationRequestHandlerSpi} interface.
     */
    private final BackchannelAuthenticationRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link BackchannelAuthenticationRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link BackchannelAuthenticationRequestHandlerSpi} interface.
     */
    public BackchannelAuthenticationRequestHandler(AuthleteApi api, BackchannelAuthenticationRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle a backchannel authentication request to a backchannel authentication
     * endpoint of CIBA (Client Initiated Backchannel Authentication).
     *
     * @param parameters
     *         Request parameters of a backchannel authentication request.
     *
     * @param authorization
     *         The value of {@code Authorization} header in the backchannel authentication
     *         request. A client application may embed its pair of client ID and
     *         client secret in a backchannel authentication request using <a href=
     *         "https://www.rfc-editor.org/rfc/rfc2617.html#section-2">Basic
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
        Params params = new Params()
                .setParameters(parameters)
                .setAuthorization(authorization)
                .setClientCertificatePath(clientCertificatePath)
                ;

        return handle(params);
    }


    /**
     * Handle a backchannel authentication request to a backchannel authentication
     * endpoint of CIBA (Client Initiated Backchannel Authentication).
     *
     * @param params
     *         Parameters for Authlete's {@code /backchannel/authentication} API.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @since 2.79
     */
    public Response handle(Params params)
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
            throw unexpected("Unexpected error in BackchannelAuthenticationRequest", t);
        }
    }


    private Response process(Params params, String clientId, String clientSecret)
    {
        // The client certificate.
        String clientCertificate = HandlerUtility
                .extractClientCertificate(params.getClientCertificatePath());

        // The second and subsequent elements in the client certificate path.
        String[] clientCertificatePath = HandlerUtility
                .extractSubsequenceFromClientCertificatePath(params.getClientCertificatePath());

        // Call Authlete's /api/backchannel/authentication API.
        BackchannelAuthenticationResponse response =
                getApiCaller().callBackchannelAuthentication(
                        params.getParameters(), clientId, clientSecret,
                        clientCertificate, clientCertificatePath,
                        params.getClientAttestation(), params.getClientAttestationPop());

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        BackchannelAuthenticationResponse.Action action = response.getAction();

        // The content of the response to the client application.
        // The format of the content varies depending on the action.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case UNAUTHORIZED:
                // 401 Unauthorized
                return ResponseUtil.unauthorized(content, CHALLENGE);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            case USER_IDENTIFICATION:
                // Process user identification.
                return handleUserIdentification(response);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/backchannel/authentication", action);
        }
    }


    private Response handleUserIdentification(BackchannelAuthenticationResponse baRes)
    {
        // Identify a user based on the hint contained in the backchannel authentication
        // request.
        User user = identifyUserByHint(baRes);

        // Check the expiration of the login hint token if necessary.
        checkExpirationOfLoginHintToken(baRes);

        // Check the user code contained in the backchannel authentication request
        // if necessary.
        checkUserCode(baRes, user);

        // Check the binding message in the backchannel authentication request
        // if necessary.
        checkBindingMessage(baRes);

        // Issue an 'auth_req_id'.
        BackchannelAuthenticationIssueResponse baiRes =
                getApiCaller().callBackchannelAuthenticationIssue(baRes.getTicket());

        // 'action' in the response denotes the next action which this service
        // implementation should take.
        BackchannelAuthenticationIssueResponse.Action action = baiRes.getAction();

        // The content of the response to the client application.
        // The format of the content varies depending on the action.
        String content = baiRes.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
            case INVALID_TICKET:
                // 500 Internal Server Error.
                return ResponseUtil.internalServerError(content);

            case OK:
                // Start communicating with the authentication device for end-user
                // authentication and authorization.
                startCommunicationWithAuthenticationDevice(user, baRes, baiRes);

                // 200 OK.
                return ResponseUtil.ok(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/backchannel/authentication/issue", action);
        }
    }


    private User identifyUserByHint(BackchannelAuthenticationResponse baRes)
    {
        // Get a user by the hint.
        User user = mSpi.getUserByHint(baRes.getHintType(), baRes.getHint(), baRes.getSub());

        if (user != null)
        {
            String subject = user.getSubject();

            if (subject != null && subject.length() > 0)
            {
                // Found a user.
                return user;
            }
        }

        // Can't identify a user by the hint.
        throw getApiCaller().backchannelAuthenticationFail(baRes.getTicket(), Reason.UNKNOWN_USER_ID);
    }


    private void checkExpirationOfLoginHintToken(BackchannelAuthenticationResponse baRes)
    {
        if (baRes.getHintType() != UserIdentificationHintType.LOGIN_HINT_TOKEN)
        {
            // The hint is not an ID token hint.
            return;
        }

        // The login hint token contained in the backchannel authentication request.
        String loingHintToken = baRes.getHint();

        // Check if the login hint token has expired or not.
        if (mSpi.isLoginHintTokenExpired(loingHintToken) == false)
        {
            // OK. The login hint token is valid.
            return;
        }

        // The login hint token has expired.
        throw getApiCaller().backchannelAuthenticationFail(baRes.getTicket(), Reason.EXPIRED_LOGIN_HINT_TOKEN);
    }


    private void checkUserCode(BackchannelAuthenticationResponse baRes, User user)
    {
        if (mSpi.shouldCheckUserCode(user, baRes) == false)
        {
            // A user code should not be checked.
            return;
        }

        // The user code contained in the backchannel authentication request.
        String userCode = baRes.getUserCode();

        if (mSpi.isValidUserCode(user, userCode))
        {
            // OK. The user code contained is valid.
            return;
        }

        // The user code is invalid.
        throw getApiCaller().backchannelAuthenticationFail(baRes.getTicket(), Reason.INVALID_USER_CODE);
    }


    private void checkBindingMessage(BackchannelAuthenticationResponse baRes)
    {
        // The binding message in the backchannel authentication request.
        String bindingMessage = baRes.getBindingMessage();

        if (bindingMessage == null || bindingMessage.length() == 0)
        {
            // The binding message is not contained in the request.
            return;
        }

        if (mSpi.isValidBindingMessage(bindingMessage))
        {
            // OK. The binding message is valid.
            return;
        }

        // The binding message is invalid.
        throw getApiCaller().backchannelAuthenticationFail(baRes.getTicket(), Reason.INVALID_BINDING_MESSAGE);
    }


    private void startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes,
            BackchannelAuthenticationIssueResponse baiRes)
    {
        // Start communicating with an authentication device for end-user authentication
        // and authorization.
        mSpi.startCommunicationWithAuthenticationDevice(user, baRes, baiRes);
    }
}
