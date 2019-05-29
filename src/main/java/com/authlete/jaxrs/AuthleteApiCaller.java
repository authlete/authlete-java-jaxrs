/*
 * Copyright (C) 2015-2018 Authlete, Inc.
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
import java.util.List;
import java.util.Map;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest.Result;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.BackchannelAuthenticationFailRequest;
import com.authlete.common.dto.BackchannelAuthenticationFailResponse;
import com.authlete.common.dto.BackchannelAuthenticationIssueRequest;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationRequest;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.dto.ClientRegistrationRequest;
import com.authlete.common.dto.ClientRegistrationResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.Property;
import com.authlete.common.dto.RevocationRequest;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.StandardIntrospectionRequest;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.TokenFailRequest;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenIssueRequest;
import com.authlete.common.dto.TokenIssueResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.dto.UserInfoIssueRequest;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoRequest;
import com.authlete.common.dto.UserInfoResponse;
import com.authlete.common.web.URLCoder;


/**
 * Utility class to call Authlete APIs.
 *
 * @author Takahiko Kawasaki
 */
class AuthleteApiCaller
{
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
        if (parameters == null)
        {
            // Authlete returns different error codes for null and an empty string.
            // 'null' is regarded as a caller's error. An empty string is regarded
            // as a client application's error.
            parameters = "";
        }

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
            String ticket, String subject, long authTime, String acr,
            Map<String, Object> claims, Property[] properties, String[] scopes)
    {
        // Create a request for /api/auth/authorization/issue API.
        AuthorizationIssueRequest request = new AuthorizationIssueRequest()
            .setTicket(ticket)
            .setSubject(subject)
            .setAuthTime(authTime)
            .setAcr(acr)
            .setProperties(properties)
            .setScopes(scopes)
            ;

        if (claims != null && claims.size() != 0)
        {
            request.setClaims(claims);
        }

        try
        {
            // Call Authlete's /api/auth/authorization/issue API.
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
            String ticket, String subject, long authTime, String acr,
            Map<String, Object> claims, Property[] properties, String[] scopes)
    {
        // Call Authlete's /api/auth/authorization/issue API.
        AuthorizationIssueResponse response =
            callAuthorizationIssue(ticket, subject, authTime, acr, claims, properties, scopes);

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
    public TokenResponse callToken(
            MultivaluedMap<String, String> parameters, String clientId, String clientSecret,
            Property[] properties, String clientCertificate, String[] clientCertificatePath)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callToken(params, clientId, clientSecret, properties, clientCertificate, clientCertificatePath);
    }


    /**
     * Call Authlete's {@code /api/auth/token} API.
     */
    private TokenResponse callToken(
            String parameters, String clientId, String clientSecret, Property[] properties, String clientCertificate, String[] clientCertificatePath)
    {
        if (parameters == null)
        {
            // Authlete returns different error codes for null and an empty string.
            // 'null' is regarded as a caller's error. An empty string is regarded
            // as a client application's error.
            parameters = "";
        }

        // Create a request for Authlete's /api/auth/token API.
        TokenRequest request = new TokenRequest()
            .setParameters(parameters)
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setProperties(properties)
            .setClientCertificate(clientCertificate)
            .setClientCertificatePath(clientCertificatePath)
            ;

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
    private TokenIssueResponse callTokenIssue(
            String ticket, String subject, Property[] properties)
    {
        // Create a request for Authlete's /api/auth/token/issue API.
        TokenIssueRequest request = new TokenIssueRequest()
            .setTicket(ticket)
            .setSubject(subject)
            .setProperties(properties)
            ;

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
    public Response tokenIssue(String ticket, String subject, Property[] properties)
    {
        // Call Authlete's /api/auth/token/issue API.
        TokenIssueResponse response = callTokenIssue(ticket, subject, properties);

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


    /**
     * Call Authlete's {@code /api/service/configuration} API.
     */
    public String callServiceConfiguration(boolean pretty)
    {
        try
        {
            // Call Authlete's /api/service/configuration API.
            return mApi.getServiceConfiguration(pretty);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/service/configuration", e);
        }
    }


    /**
     * Get the JWK Set of the service. This method calls Authlete's
     * {@code /api/service/jwks/get} API.
     */
    public Response serviceJwksGet(
            boolean pretty, boolean includePrivateKeys) throws AuthleteApiException
    {
        try
        {
            // Call Authlete's /api/service/jwks/get API.
            String jwks = mApi.getServiceJwks(pretty, includePrivateKeys);

            if (jwks == null || jwks.length() == 0)
            {
                // 204 No Content
                return ResponseUtil.noContent();
            }

            // Response as "application/json;charset=UTF-8" with 200 OK.
            return ResponseUtil.ok(jwks);
        }
        catch (AuthleteApiException e)
        {
            // If the status code is not 302 Found.
            if (e.getStatusCode() != Status.FOUND.getStatusCode())
            {
                // The API call failed.
                throw apiFailure("/api/service/jwks/get", e);
            }

            // The value of 'Location' header.
            String location = getFirst(e.getResponseHeaders(), "Location");

            // 302 Found with Location header.
            return ResponseUtil.location(location);
        }
    }


    private static String getFirst(Map<String, List<String>> map, String key)
    {
        if (map == null)
        {
            return null;
        }

        List<String> list = map.get(key);

        if (list == null || list.size() == 0)
        {
            return null;
        }

        return list.get(0);
    }


    /**
     * Call Authlete's {@code /api/auth/revocation} API.
     */
    public RevocationResponse callRevocation(MultivaluedMap<String, String> parameters, String clientId, String clientSecret)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callRevocation(params, clientId, clientSecret);
    }


    /**
     * Call Authlete's {@code /api/auth/revocation} API.
     */
    private RevocationResponse callRevocation(String parameters, String clientId, String clientSecret)
    {
        if (parameters == null)
        {
            // Authlete returns different error codes for null and an empty string.
            // 'null' is regarded as a caller's error. An empty string is regarded
            // as a client application's error.
            parameters = "";
        }

        // Create a request for Authlete's /api/auth/revocation API.
        RevocationRequest request = new RevocationRequest()
            .setParameters(parameters)
            .setClientId(clientId)
            .setClientSecret(clientSecret);

        try
        {
            // Call Authlete's /api/auth/revocation API.
            return mApi.revocation(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/revocation", e);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/userinfo} API.
     */
    public UserInfoResponse callUserInfo(String accessToken)
    {
        // Create a request for Authlete's /api/auth/userinfo API.
        UserInfoRequest request = new UserInfoRequest()
            .setToken(accessToken);

        try
        {
            // Call Authlete's /api/auth/userinfo API.
            return mApi.userinfo(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/userinfo", e);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/userinfo/issue} API.
     */
    private UserInfoIssueResponse callUserInfoIssue(String accessToken, Map<String, Object> claims)
    {
        // Create a request for /api/auth/userinfo/issue API.
        UserInfoIssueRequest request = new UserInfoIssueRequest()
            .setToken(accessToken);

        if (claims != null && claims.size() != 0)
        {
            request.setClaims(claims);
        }

        try
        {
            // Call Authlete's /api/auth/userinfo/issue API.
            return mApi.userinfoIssue(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/userinfo/issue", e);
        }
    }


    /**
     * Issue a JSON or a JWT containing user information.
     */
    public Response userInfoIssue(String accessToken, Map<String, Object> claims)
    {
        // Call Authlete's /api/auth/userinfo/issue API.
        UserInfoIssueResponse response = callUserInfoIssue(accessToken, claims);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        UserInfoIssueResponse.Action action = response.getAction();

        // The content of the response to the client application.
        // The format of the content varies depending on the action.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.bearerError(Status.INTERNAL_SERVER_ERROR, content);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.bearerError(Status.BAD_REQUEST, content);

            case UNAUTHORIZED:
                // 401 Unauthorized
                return ResponseUtil.bearerError(Status.UNAUTHORIZED, content);

            case FORBIDDEN:
                // 403 Forbidden
                return ResponseUtil.bearerError(Status.FORBIDDEN, content);

            case JSON:
                // 200 OK, application/json;charset=UTF-8
                return ResponseUtil.ok(content);

            case JWT:
                // 200 OK, application/jwt
                return ResponseUtil.ok(content, ResponseUtil.MEDIA_TYPE_JWT);

            default:
                // This never happens.
                throw unknownAction("/api/auth/userinfo/issue", action);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/introspection} API.
     */
    public IntrospectionResponse callIntrospection(String accessToken, String[] scopes, String subject, String clientCertificate)
    {
        // Create a request for /api/auth/introspection API.
        IntrospectionRequest request = new IntrospectionRequest()
            .setToken(accessToken)
            .setScopes(scopes)
            .setSubject(subject)
            .setClientCertificate(clientCertificate);

        try
        {
            // Call Authlete's /api/auth/introspection API.
            return mApi.introspection(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/introspection", e);
        }
    }


    /**
     * Call Authlete's {@code /api/auth/introspection/standard} API.
     */
    public StandardIntrospectionResponse callStandardIntrospection(MultivaluedMap<String, String> parameters)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callStandardIntrospection(params);
    }


    /**
     * Call Authlete's {@code /api/auth/introspection/standard} API.
     */
    private StandardIntrospectionResponse callStandardIntrospection(String parameters)
    {
        if (parameters == null)
        {
            // Authlete returns different error codes for null and an empty string.
            // 'null' is regarded as a caller's error. An empty string is regarded
            // as a client application's error.
            parameters = "";
        }

        // Create a request for Authlete's /api/auth/introspection/standard API.
        StandardIntrospectionRequest request = new StandardIntrospectionRequest()
            .setParameters(parameters);

        try
        {
            // Call Authlete's /api/auth/introspection/standard API.
            return mApi.standardIntrospection(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/auth/introspection/standard", e);
        }
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication} API.
     */
    public BackchannelAuthenticationResponse callBackchannelAuthentication(
            MultivaluedMap<String, String> parameters, String clientId, String clientSecret,
            String clientCertificate, String[] clientCertificatePath)
    {
        String params = URLCoder.formUrlEncode(parameters);

        return callBackchannelAuthentication(params, clientId, clientSecret, clientCertificate, clientCertificatePath);
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication} API.
     */
    private BackchannelAuthenticationResponse callBackchannelAuthentication(
            String parameters, String clientId, String clientSecret,
            String clientCertificate, String[] clientCertificatePath)
    {
        if (parameters == null)
        {
            // Authlete returns different error codes for null and an empty string.
            // 'null' is regarded as a caller's error. An empty string is regarded
            // as a client application's error.
            parameters = "";
        }

        // Create a request for Authlete's /api/backchannel/authentication API.
        BackchannelAuthenticationRequest request = new BackchannelAuthenticationRequest()
            .setParameters(parameters)
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setClientCertificate(clientCertificate)
            .setClientCertificatePath(clientCertificatePath)
            ;

        try
        {
            // Call Authlete's /api/backchannel/authentication API.
            return mApi.backchannelAuthentication(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/backchannel/authentication", e);
        }
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication/fail} API.
     */
    private BackchannelAuthenticationFailResponse callBackchannelAuthenticationFail(String ticket, BackchannelAuthenticationFailRequest.Reason reason)
    {
        // Create a request for /api/backchannel/authentication/fail API.
        BackchannelAuthenticationFailRequest request = new BackchannelAuthenticationFailRequest()
            .setTicket(ticket)
            .setReason(reason)
            ;

        try
        {
            // Call Authlete's /api/backchannel/authentication/fail API.
            return mApi.backchannelAuthenticationFail(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/backchannel/authentication/fail", e);
        }
    }


    /**
     * Create a response that describes the failure. This method
     * calls Authlete's {@code /api/backchannel/authentication/fail} API.
     */
    private Response createBackchannelAuthenticationFailResponse(String ticket, BackchannelAuthenticationFailRequest.Reason reason)
    {
        // Call Authlete's /api/backchannel/authentication/fail API.
        BackchannelAuthenticationFailResponse response = callBackchannelAuthenticationFail(ticket, reason);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        BackchannelAuthenticationFailResponse.Action action = response.getAction();

        // The content of the response to the client application.
        // The format of the content varies depending on the action.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case FORBIDDEN:
                // 403 Forbidden.
                return ResponseUtil.forbidden(content);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            default:
                // This never happens.
                throw unknownAction("/api/backchannel/authentication/fail", action);
        }
    }


    /**
     * Create an exception that describes the failure. This method
     * calls Authlete's {@code /api/backchannel/authentication/fail} API.
     */
    public WebApplicationException backchannelAuthenticationFail(String ticket, BackchannelAuthenticationFailRequest.Reason reason)
    {
        // Create a response to the client application with the help of
        // Authlete's /api/backchannel/authentication/fail API.
        Response response = createBackchannelAuthenticationFailResponse(ticket, reason);

        // Create an exception containing the response.
        return new WebApplicationException(response);
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication/issue} API.
     */
    public BackchannelAuthenticationIssueResponse callBackchannelAuthenticationIssue(String ticket)
    {
        // Create a request for /api/backchannel/authentication/issue API.
        BackchannelAuthenticationIssueRequest request = new BackchannelAuthenticationIssueRequest()
            .setTicket(ticket)
            ;

        try
        {
            // Call Authlete's /api/backchannel/authentication/issue API.
            return mApi.backchannelAuthenticationIssue(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/backchannel/authentication/issue", e);
        }
    }


    /**
     * Call Authlete's {@code /api/backchannel/authentication/complete} API.
     */
    public BackchannelAuthenticationCompleteResponse callBackchannelAuthenticationComplete(
            String ticket, String subject, Result result, long authTime, String acr,
            Map<String, Object> claims, Property[] properties, String[] scopes,
            String errorDescription, URI errorUri)
    {
        // Create a request for /api/backchannel/authentication/complete API.
        BackchannelAuthenticationCompleteRequest request = new BackchannelAuthenticationCompleteRequest()
            .setTicket(ticket)
            .setSubject(subject)
            .setResult(result)
            .setAuthTime(authTime)
            .setAcr(acr)
            .setProperties(properties)
            .setScopes(scopes)
            .setErrorDescription(errorDescription)
            .setErrorUri(errorUri)
            ;

        if (claims != null && claims.size() != 0)
        {
            request.setClaims(claims);
        }

        try
        {
            // Call Authlete's /api/backchannel/authentication/complete API.
            return mApi.backchannelAuthenticationComplete(request);
        }
        catch (AuthleteApiException e)
        {
            // The API call failed.
            throw apiFailure("/api/backchannel/authentication/complete", e);
        }
    }


    /**
     * Call Authlete's {@code /api/client/registration} API.
     */
    public ClientRegistrationResponse callClientRegistration(
            String json)
    {
        return callClientRegistration(json, null);
    }


    /**
     * Call Authlete's {@code /api/client/registration} API
     * with an initial access token.
     */
    public ClientRegistrationResponse callClientRegistration(
            String json, String initialAccessToken)
    {
        ClientRegistrationRequest request = new ClientRegistrationRequest()
                .setJson(json)
                .setToken(initialAccessToken); // TODO: we should mark this field as the initial access
                                               //       token and not use the registration access token field

        try
        {
            return mApi.registerClient(request);
        }
        catch (AuthleteApiException e)
        {
            throw apiFailure("/api/client/registration", e);
        }
    }


    /**
     * Call Authlete's {@code /api/client/registration/get} API.
     */
    public ClientRegistrationResponse callClientRegistrationGet(
            String clientId, String registrationAccessToken)
    {
        ClientRegistrationRequest request = new ClientRegistrationRequest()
                .setClientId(clientId)
                .setToken(registrationAccessToken);

        try
        {
            return mApi.dynamicClientGet(request);
        }
        catch (AuthleteApiException e)
        {
            throw apiFailure("/api/client/registration/get", e);
        }
    }


    /**
     * Call Authlete's {@code /api/client/registration/update} API.
     */
    public ClientRegistrationResponse callClientRegistrationUpdate(
            String clientId, String json, String registrationAccessToken)
    {
        ClientRegistrationRequest request = new ClientRegistrationRequest()
                .setClientId(clientId)
                .setJson(json)
                .setToken(registrationAccessToken);

        try
        {
            return mApi.dynamicClientUpdate(request);
        }
        catch (AuthleteApiException e)
        {
            throw apiFailure("/api/client/registration/update", e);
        }
    }


    /**
     * Call Authlete's {@code /api/client/registration/delete} API.
     */
    public ClientRegistrationResponse callClientRegistrationDelete(
            String clientId, String registrationAccessToken)
    {
        ClientRegistrationRequest request = new ClientRegistrationRequest()
                .setClientId(clientId)
                .setToken(registrationAccessToken);

        try
        {
            return mApi.dynamicClientDelete(request);
        }
        catch (AuthleteApiException e)
        {
            throw apiFailure("/api/client/registration/delete", e);
        }
    }
}