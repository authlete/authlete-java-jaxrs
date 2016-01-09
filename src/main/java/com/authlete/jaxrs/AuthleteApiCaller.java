/*
 * Copyright (C) 2015-2016 Authlete, Inc.
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
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.TokenFailRequest;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenIssueRequest;
import com.authlete.common.dto.TokenIssueResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.web.URLCoder;
import com.google.gson.Gson;


/**
 * Utility class to call Authlete APIs.
 *
 * @author Takahiko Kawasaki
 */
class AuthleteApiCaller
{
    private static final Gson GSON = new Gson();


    /**
     * Implementation of {@link AuthleteApi} interface.
     */
    private final AuthleteApi mApi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     */
    AuthleteApiCaller(AuthleteApi api)
    {
        mApi = api;
    }


    /**
     * Create an {@link InternalServerErrorException} instance to indicate
     * that an Authlete API call failed.
     */
    private InternalServerErrorException apiFailure(String path, AuthleteApiException e)
    {
        // Error message.
        String message = String.format("Authlete %s API failed: %s", path, e.getMessage());

        // Response body in the response from the Authlete server.
        if (e.getResponseBody() != null)
        {
            // Append the content of the response body to the error message.
            message = new StringBuilder(message)
                    .append(": ").append(e.getResponseBody()).toString();
        }

        // 500 Internal Server Error
        return internalServerError(message, e);
    }


    /**
     * Create an {@link InternalServerErrorException} instance to indicate
     * that the value of {@code action} parameter contained in a response
     * from an Authlete API is unknown.
     */
    public InternalServerErrorException unknownAction(String path, Enum<?> action)
    {
        // Error message.
        String message = String.format("Authlete %s API returned an unknown action: %s", path, action);

        // 500 Internal Server Error
        return internalServerError(message, null);
    }


    /**
     * Create an {@link InternalServerErrorException} instance having
     * a response body.
     */
    private InternalServerErrorException internalServerError(String message, Throwable cause)
    {
        Response response = ResponseUtil.internalServerError(message, MediaType.TEXT_PLAIN_TYPE);

        if (cause != null)
        {
            return new InternalServerErrorException(message, response, cause);
        }
        else
        {
            return new InternalServerErrorException(message, response);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/authorization} API.
     */
    public AuthorizationResponse callAuthorization(MultivaluedMap<String, String> parameters)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callAuthorization(params);
    }


    /**
     * Call Authlete's {@code /api/auth/authorization} API.
     */
    private AuthorizationResponse callAuthorization(String parameters)
    {
        // Create a request for Authlete's /api/auth/authorization API.
        AuthorizationRequest request = new AuthorizationRequest()
            .setParameters(parameters);

        try
        {
            // Call Authlete's /api/auth/authorization API.
            return mApi.authorization(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/authorization", e);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/authorization/fail} API.
     */
    private AuthorizationFailResponse callAuthorizationFail(String ticket, AuthorizationFailRequest.Reason reason)
    {
        // Create a request for /api/auth/authorization/fail API.
        AuthorizationFailRequest request = new AuthorizationFailRequest()
            .setTicket(ticket)
            .setReason(reason);

        try
        {
            // Call Authlete's /api/auth/authorization/fail API.
            return mApi.authorizationFail(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/authorization/fail", e);
        }
    }


    /**
     * Create a response that describes the failure. This method
     * calls Authlete's {@code /api/auth/authorization/fail} API.
     */
    private Response createAuthorizationFailResponse(String ticket, AuthorizationFailRequest.Reason reason)
    {
        // Call Authlete's /api/auth/authorization/fail API.
        AuthorizationFailResponse response = callAuthorizationFail(ticket, reason);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        AuthorizationFailResponse.Action action = response.getAction();

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

            default:
                // This never happens.
                throw unknownAction("/api/auth/authorization/fail", action);
        }
    }


    /**
     * Create an exception that describes the failure. This method
     * calls Authlete's {@code /api/auth/authorization/fail} API.
     */
    public WebApplicationException authorizationFail(String ticket, AuthorizationFailRequest.Reason reason)
    {
        // Create a response to the client application with the help of
        // Authlete's /api/auth/authorization/fail API.
        Response response = createAuthorizationFailResponse(ticket, reason);

        // Create an exception containing the response.
        return new WebApplicationException(response);
    }


    /**
     * Call Authlete's {@code /api/auth/authorization/issue} API.
     */
    private AuthorizationIssueResponse callAuthorizationIssue(
            String ticket, String subject, long authTime, String acr, Map<String, Object> claims)
    {
        // Create a request for /api/auth/authorization/issue API.
        AuthorizationIssueRequest request = new AuthorizationIssueRequest()
            .setTicket(ticket)
            .setSubject(subject)
            .setAuthTime(authTime / 1000L)
            .setAcr(acr);

        if (claims != null && claims.size() != 0)
        {
            request.setClaims(GSON.toJson(claims));
        }

        try
        {
            // Call Authlete's /auth/authorization/issue API.
            return mApi.authorizationIssue(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/authorization/issue", e);
        }
    }


    /**
     * Issue an authorization code, an ID token and/or an access token.
     * This method calls Authlete's {@code /api/auth/authorization/issue} API.
     */
    public Response authorizationIssue(
            String ticket, String subject, long authTime, String acr, Map<String, Object> claims)
    {
        // Call Authlete's /api/auth/authorization/issue API.
        AuthorizationIssueResponse response =
            callAuthorizationIssue(ticket, subject, authTime, acr, claims);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        AuthorizationIssueResponse.Action action = response.getAction();

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

            default:
                // This never happens.
                throw unknownAction("/api/auth/authorization/issue", action);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/token} API.
     */
    public TokenResponse callToken(MultivaluedMap<String, String> parameters, String clientId, String clientSecret)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callToken(params, clientId, clientSecret);
    }


    /**
     * Call Authlete's {@code /api/auth/token} API.
     */
    private TokenResponse callToken(String parameters, String clientId, String clientSecret)
    {
        // Create a request for Authlete's /api/auth/token API.
        TokenRequest request = new TokenRequest()
            .setParameters(parameters)
            .setClientId(clientId)
            .setClientSecret(clientSecret);

        try
        {
            // Call Authlete's /api/auth/token API.
            return mApi.token(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/token", e);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/token/fail} API.
     */
    private TokenFailResponse callTokenFail(String ticket, TokenFailRequest.Reason reason)
    {
        // Create a request for /api/auth/token/fail API.
        TokenFailRequest request = new TokenFailRequest()
            .setTicket(ticket)
            .setReason(reason);

        try
        {
            // Call Authlete's /api/auth/token/fail API.
            return mApi.tokenFail(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/token/fail", e);
        }
    }


    /**
     * Create a response that describes the failure. This method
     * calls Authlete's {@code /api/auth/token/fail} API.
     */
    private Response createTokenFailResponse(String ticket, TokenFailRequest.Reason reason)
    {
        // Call Authlete's /api/auth/token/fail API.
        TokenFailResponse response = callTokenFail(ticket, reason);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        TokenFailResponse.Action action = response.getAction();

        // The content of the response to the client application.
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

            default:
                // This never happens.
                throw unknownAction("/api/auth/token/fail", action);
        }
    }


    /**
     * Create an exception that describes the failure. This method
     * calls Authlete's {@code /api/auth/token/fail} API.
     */
    public WebApplicationException tokenFail(String ticket, TokenFailRequest.Reason reason)
    {
        // Create a response to the client application with the help of
        // Authlete's /api/auth/token/fail API.
        Response response = createTokenFailResponse(ticket, reason);

        // Create an exception containing the response.
        return new WebApplicationException(response);
    }


    /**
     * Call Authlete's {@code /api/auth/token/issue} API.
     */
    private TokenIssueResponse callTokenIssue(String ticket, String subject)
    {
        // Create a request for Authlete's /api/auth/token/issue API.
        TokenIssueRequest request = new TokenIssueRequest()
            .setTicket(ticket)
            .setSubject(subject);

        try
        {
            // Call Authlete's /api/auth/token/issue API.
            return mApi.tokenIssue(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/token/issue", e);
        }
    }


    /**
     * Issue an access token and optionally an ID token.
     * This method calls Authlete's {@code /api/auth/token/issue} API.
     */
    public Response tokenIssue(String ticket, String subject)
    {
        // Call Authlete's /api/auth/token/issue API.
        TokenIssueResponse response = callTokenIssue(ticket, subject);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        TokenIssueResponse.Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case OK:
                // 200 OK
                return ResponseUtil.ok(content);

            default:
                // This never happens.
                throw unknownAction("/api/auth/token/issue", action);
        }
    }
}
