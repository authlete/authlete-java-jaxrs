/*
 * Copyright (C) 2015-2019 Authlete, Inc.
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


import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.AuthorizationFailRequest.Reason;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Property;
import com.authlete.jaxrs.spi.AuthorizationRequestHandlerSpi;


/**
 * Handler for authorization requests to a <a href=
 * "https://tools.ietf.org/html/rfc6749#section-3.1">authorization endpoint</a>
 * of OAuth 2.0 (<a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>).
 *
 * <p>
 * In an implementation of authorization endpoint, call {@link
 * #handle(MultivaluedMap) handle()} method and use the response as the response
 * from the endpoint to the client application. {@code handle()} method calls
 * Authlete's {@code /api/auth/authorization} API, receives a response from
 * the API, and dispatches processing according to the {@code action} parameter
 * in the response.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class AuthorizationRequestHandler extends BaseHandler
{
    /**
     * Implementation of {@link AuthorizationRequestHandlerSpi} interface.
     */
    private final AuthorizationRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link AuthorizationRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link AuthorizationRequestHandlerSpi} interface.
     */
    public AuthorizationRequestHandler(AuthleteApi api, AuthorizationRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle an authorization request to a <a href=
     * "https://tools.ietf.org/html/rfc6749#section-3.1">authorization endpoint</a>
     * of OAuth 2.0 (<a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a>).
     *
     * @param parameters
     *         Request parameters of an authorization request.
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
            throw unexpected("Unexpected error in AuthorizationRequestHandler", t);
        }
    }


    /**
     * Process the authorization request.
     */
    private Response process(MultivaluedMap<String, String> parameters)
    {
        // Call Authlete's /api/auth/authorization API.
        AuthorizationResponse response = getApiCaller().callAuthorization(parameters);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        AuthorizationResponse.Action action = response.getAction();

        // The content of the response to the client application.
        // The format of the content varies depending on the action.
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

            case LOCATION:
                // 302 Found
                return ResponseUtil.location(content);

            case FORM:
                // 200 OK
                return ResponseUtil.form(content);

            case INTERACTION:
                // Process the authorization request with user interaction.
                return handleInteraction(response);

            case NO_INTERACTION:
                // Process the authorization request without user interaction.
                // The flow reaches here only when the authorization request
                // contained prompt=none.
                return handleNoInteraction(response);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/authorization", action);
        }
    }


    /**
     * Handle the case where {@code action} parameter in a response from
     * Authlete's {@code /api/auth/authorization} API is {@code INTERACTION}.
     */
    private Response handleInteraction(AuthorizationResponse response)
    {
        return mSpi.generateAuthorizationPage(response);
    }


    /**
     * Handle the case where {@code action} parameter in a response from
     * Authlete's {@code /api/auth/authorization} API is {@code NO_INTERACTION}.
     */
    private Response handleNoInteraction(AuthorizationResponse response)
    {
        // Check 1. End-User Authentication
        noInteractionCheckAuthentication(response);

        // Get the time when the user was authenticated.
        long authTime = mSpi.getUserAuthenticatedAt();

        // Check 2. Max Age
        noInteractionCheckMaxAge(response, authTime);

        // The current subject, i.e. the unique ID assigned by
        // the service to the current user.
        String subject = mSpi.getUserSubject();

        // get a potentially pairwise subject based on the user and the client
        String sub = mSpi.getSub();

        // Check 3. Subject
        noInteractionCheckSubject(response, subject);

        // Get the ACR that was satisfied when the current user
        // was authenticated.
        String acr = mSpi.getAcr();

        // Check 4. ACR
        noInteractionCheckAcr(response, acr);

        // Extra properties to associate with an access token and/or
        // an authorization code.
        Property[] properties = mSpi.getProperties();

        // Scopes to associate with an access token and/or an authorization code.
        // If a non-null value is returned from mSpi.getScopes(), the scope set
        // replaces the scopes that have been specified in the original
        // authorization request.
        String[] scopes = mSpi.getScopes();

        // Issue
        return noInteractionIssue(response, authTime, subject, acr, properties, scopes, sub);
    }


    /**
     * Check whether an end-user has already logged in or not.
     */
    private void noInteractionCheckAuthentication(AuthorizationResponse response)
    {
        // If the current user has already been authenticated.
        if (mSpi.isUserAuthenticated())
        {
            // OK.
            return;
        }

        // A user must have logged in.
        throw getApiCaller().authorizationFail(response.getTicket(), Reason.NOT_LOGGED_IN);
    }


    private void noInteractionCheckMaxAge(AuthorizationResponse response, long authTime)
    {
        // Get the requested maximum authentication age.
        int maxAge = response.getMaxAge();

        // If no maximum authentication age is requested.
        if (maxAge == 0)
        {
            // No check is needed.
            return;
        }

        // The time at which the authentication expires.
        long expiresAtMillis = (authTime + maxAge) * 1000L;

        // If the authentication has not expired yet.
        if (System.currentTimeMillis() < expiresAtMillis)
        {
            // OK.
            return;
        }

        // The maximum authentication age has elapsed.
        throw getApiCaller().authorizationFail(response.getTicket(), Reason.EXCEEDS_MAX_AGE);
    }


    private void noInteractionCheckSubject(AuthorizationResponse response, String subject)
    {
        // Get the requested subject.
        String requestedSubject = response.getSubject();

        // If no subject is requested.
        if (requestedSubject == null)
        {
            // No check is needed.
            return;
        }

        // If the requested subject matches the current user.
        if (requestedSubject.equals(subject))
        {
            // OK.
            return;
        }

        // The current user is different from the requested subject.
        throw getApiCaller().authorizationFail(response.getTicket(), Reason.DIFFERENT_SUBJECT);
    }


    private void noInteractionCheckAcr(AuthorizationResponse response, String acr)
    {
        // Get the list of requested ACRs.
        String[] requestedAcrs = response.getAcrs();

        // If no ACR is requested.
        if (requestedAcrs == null || requestedAcrs.length == 0)
        {
            // No check is needed.
            return;
        }

        for (String requestedAcr : requestedAcrs)
        {
            if (requestedAcr.equals(acr))
            {
                // OK. The ACR satisfied when the current user was
                // authenticated matches one of the requested ACRs.
                return;
            }
        }

        // If one of the requested ACRs must be satisfied.
        if (response.isAcrEssential())
        {
            // None of the requested ACRs is satisfied.
            throw getApiCaller().authorizationFail(response.getTicket(), Reason.ACR_NOT_SATISFIED);
        }

        // The ACR satisfied when the current user was authenticated
        // does not match any one of the requested ACRs, but the
        // authorization request from the client application did
        // not request ACR as essential. Therefore, it is not
        // necessary to raise an error here.
    }


    private Response noInteractionIssue(
            AuthorizationResponse response, long authTime, String subject,
            String acr, Property[] properties, String[] scopes, String sub)
    {
        // When prompt=none is contained in an authorization request,
        // response.getClaims() returns null. This means that user
        // claims don't have to be collected. In other words, if an
        // authorization request contains prompt=none and requests
        // user claims at the same time, Authlete regards such a
        // request as illegal, because Authlete does not provide any
        // means to pre-configure consent for claims.
        //
        // See the description about prompt=none in "OpenID Connect
        // Core 1.0, 3.1.2.1. Authentication Request" for details.

        return getApiCaller().authorizationIssue(
            response.getTicket(), subject, authTime, acr,
                (Map<String, Object>) null, properties, scopes, sub);
    }
}
