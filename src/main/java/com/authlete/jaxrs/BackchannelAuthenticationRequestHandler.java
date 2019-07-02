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
import com.authlete.common.dto.BackchannelAuthenticationFailRequest.Reason;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.types.User;
import com.authlete.common.types.UserIdentificationHintType;
import com.authlete.common.web.BasicCredentials;
import com.authlete.jaxrs.spi.BackchannelAuthenticationRequestHandlerSpi;


/**
 * Handler for backchannel authentication requests to a backchannel authentication
 * endpoint of CIBA (Client Initiated Backchannel Authentication).
 *
 * <p>
 * In an implementation of backchannel authentication endpoint, call {@link #handle(MultivaluedMap, String, String[])
 * handle()} method and use the response as the response from the endpoint to the
 * client application. {@code handle()} method calls Authlete's {@code /api/backchannel/authentication}
 * API, receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @author Hideki Ikeda
 *
 * @since 2.13
 */
public class BackchannelAuthenticationRequestHandler extends BaseHandler
{
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
            throw unexpected("Unexpected error in BackchannelAuthenticationRequest", t);
        }
    }


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

        // Call Authlete's /api/backchannel/authentication API.
        BackchannelAuthenticationResponse response =
                getApiCaller().callBackchannelAuthentication(parameters, clientId, clientSecret, clientCertificate, clientCertificatePath);

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
