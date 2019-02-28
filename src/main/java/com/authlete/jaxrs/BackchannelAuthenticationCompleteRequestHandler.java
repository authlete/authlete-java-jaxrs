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


import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.Property;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest.Result;
import com.authlete.jaxrs.spi.BackchannelAuthenticationCompleteRequestHandlerSpi;


/**
 * Handler for the result of end-user authentication and authorization in CIBA
 * (Client Initiated Backchannel Authentication) flow.
 *
 * <p>
 * {@link #handle(String, String[]) handle()} method should be called after the
 * authorization server receives the result of end-user authentication and authorization
 * from the authentication device, or even in the case where the server gave up
 * receiving a response from the authentication device for some reasons. {@code handle()}
 * method calls Authlete's {@code /api/backchannel/authentication/complete} API,
 * receives a response from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @author Hideki Ikeda
 *
 * @since 2.13
 */
public class BackchannelAuthenticationCompleteRequestHandler extends BaseHandler
{
    /**
     * Implementation of {@link BackchannelAuthenticationCompleteRequestHandlerSpi}
     * interface.
     */
    private final BackchannelAuthenticationCompleteRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link BackchannelAuthenticationCompleteRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link BackchannelAuthenticationCompleteRequestHandlerSpi} interface.
     */
    public BackchannelAuthenticationCompleteRequestHandler(AuthleteApi api, BackchannelAuthenticationCompleteRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle the result of end-user authentication and authorization in CIBA
     * (Client Initiated Backchannel Authentication) flow.
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/backchannel/authentication}
     *         API.
     *
     * @param claimNames
     *         Names of requested claims. Use the value of the {@code claims}
     *         parameter in a response from Authlete's {@code /api/backchannel/authentication}
     *         API.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public void handle(String ticket, String[] claimNames) throws WebApplicationException
    {
        try
        {
            // Process the given parameters.
            process(ticket, claimNames);
        }
        catch (WebApplicationException e)
        {
            // Authlete API error or cd communication error.
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in BackchannelAuthenticationCompleteRequestHandler", t);
        }
    }


    private void process(String ticket, String[] claimNames)
    {
        // Complete the process with the result of end-user authentication and
        // authorization.
        BackchannelAuthenticationCompleteResponse response = complete(ticket, claimNames);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        BackchannelAuthenticationCompleteResponse.Action action = response.getAction();

        // Dispatch according to the action.
        switch (action)
        {
            case SERVER_ERROR:
                // Server error.
                handleServerError(response);
                return;

            case NO_ACTION:
                // No action is required. This happens when the backchannel token
                // delivery mode is "poll".
                return;

            case NOTIFICATION:
                // Send a notification to the client. This happens when the backchannel
                // token delivery mode is "ping" or "push".
                handleNotification(response);
                return;

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/backchannel/authentication/complete", action);
        }
    }


    private BackchannelAuthenticationCompleteResponse complete(String ticket, String[] claimNames)
    {
        // Get the authentication result.
        Result result = mSpi.getResult();

        // Get the subject of the user.
        String subject = mSpi.getUserSubject();

        if (result != Result.AUTHORIZED)
        {
            // Get the description of the error.
            String errorDescription = mSpi.getErrorDescription();

            // Get the URI of a document which describes the error in detail.
            URI errorUri = mSpi.getErrorUri();

            // The end-user authorization has not been successfully done.
            // Then, complete the process with failure.
            return fail(ticket, subject, result, errorDescription, errorUri);
        }

        // OK. The end-user has successfully authorized the client.

        // Get the authentication time.
        long authTime = mSpi.getUserAuthenticatedAt();

        // Collect the user's claims.
        Map<String, Object> claims = collectClaims(claimNames);

        // Get the acr value that was actually used.
        String acr = mSpi.getAcr();

        // Scopes to associate with an access token.
        // If a non-null value is returned from mSpi.getScopes(), the scope set
        // replaces the scopes that have been specified in the original
        // backchannel authentication request.
        String[] scopes = mSpi.getScopes();

        // Properties to associate with an access token.
        Property[] properties = mSpi.getProperties();

        // Complete the process with successful authorization.
        return authorize(ticket, subject, authTime, acr, claims, properties, scopes);
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication/complete} API with an unsuccessful
     * result.
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/backchannel/authentication}
     *         API.
     *
     * @param subject
     *         The subject of the authenticated user.
     *
     * @param result
     *         The result of end-user authentication and authorization.
     *
     * @param errorDescription
     *         The description of the error.
     *
     * @param errorUri
     *         The URI of a document which describes the error in detail.
     *
     * @return
     *         A response from Authlete's {@code /api/backchannel/authentication/complete}
     *         API.
     */
    private BackchannelAuthenticationCompleteResponse fail(
            String ticket, String subject, Result result, String errorDescription,
            URI errorUri)
    {
        return callBackchannelAuthenticationComplete(
                ticket, subject, result, 0, null, null, null, null, errorDescription,
                errorUri);
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication/complete} API with
     * successful authorization.
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/backchannel/authentication}
     *         API.
     *
     * @param subject
     *         The subject (= unique identifier) of the end-user.
     *
     * @param authTime
     *         The time when end-user authentication occurred. The number of
     *         seconds since Unix epoch (1970-01-01). This value is used as
     *         the value of {@code auth_time} claim in an ID token that may
     *         be issued. Pass 0 if the time is unknown.
     *
     * @param acr
     *         The authentication context class reference that the end-user
     *         authentication satisfied. This value is used as the value of
     *         {@code acr} claim in an ID token that may be issued. Pass
     *         {@code null} if ACR is unknown.
     *
     * @param claims
     *         Pairs of claim key and claim value. The pairs are embedded
     *         in an ID token that may be issued. Passing {@code null} means
     *         that values of the requested claims are not available.
     *
     * @param properties
     *         Extra properties to associate with an access token.
     *
     * @param scopes
     *         Scopes to associate with an access token. If {@code null} is given,
     *         the scopes contained in the original backchannel authentication
     *         request are used. Otherwise, the scopes given to this method replace
     *         the scopes.
     *
     * @return
     *         A response from Authlete's {@code /api/backchannel/authentication/complete}
     *         API.
     */
    private BackchannelAuthenticationCompleteResponse authorize(
            String ticket, String subject, long authTime, String acr, Map<String, Object> claims,
            Property[] properties, String[] scopes)
    {
        return callBackchannelAuthenticationComplete(
                ticket, subject, Result.AUTHORIZED, authTime, acr, claims, properties,
                scopes, null, null);
    }


    private BackchannelAuthenticationCompleteResponse callBackchannelAuthenticationComplete(
            String ticket, String subject, Result result, long authTime, String acr,
            Map<String, Object> claims, Property[] properties, String[] scopes,
            String errorDescription, URI errorUri)
    {
        return getApiCaller().callBackchannelAuthenticationComplete(
                ticket, subject, result, authTime, acr, claims, properties, scopes,
                errorDescription, errorUri);
    }


    private void handleServerError(BackchannelAuthenticationCompleteResponse response)
    {
        // The result message.
        String message = response.getResultMessage();

        // Create an error response.
        Response errorResponse = ResponseUtil.internalServerError(message, MediaType.TEXT_PLAIN_TYPE);

        // Throw an internal server error exception.
        throw new InternalServerErrorException(errorResponse);
    }


    private Map<String, Object> collectClaims(String[] requestedClaimNames)
    {
        if (requestedClaimNames == null || requestedClaimNames.length == 0)
        {
            // No claim is requested by the client.
            return null;
        }

        // Claim values.
        Map<String, Object> claims = new HashMap<String, Object>();

        for (String name : requestedClaimNames)
        {
            if (name == null || name.length() == 0)
            {
                continue;
            }

            Object value = mSpi.getUserClaim(name);

            if (value == null)
            {
                continue;
            }

            claims.put(name, value);
        }

        if (claims.size() == 0)
        {
            return null;
        }

        return claims;
    }


    private void handleNotification(BackchannelAuthenticationCompleteResponse bacRes)
    {
        // Send the notification to the client.
        mSpi.sendNotification(bacRes);
    }
}
