/*
 * Copyright (C) 2016-2018 Authlete, Inc.
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


import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.IntrospectionResponse.Action;


/**
 * Access token validator.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class AccessTokenValidator extends BaseHandler
{
    private static final String CHALLENGE_ON_MISSING_ACCESS_TOKEN
        = "Bearer error=\"invalid_token\",error_description=\"An access token is missing.\"";


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public AccessTokenValidator(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validate(String, String[], String)
     * validate}<code>(accessToken, null, null)</code>.
     *
     * </p>
     * When the given access token is not valid, this method throws a
     * {@link WebApplicationException}. The response contained in the
     * exception complies with the requirements described in <a href=
     * "http://tools.ietf.org/html/rfc6750">RFC 6750</a> (The OAuth
     * 2.0 Authorization Framework: Bearer Token Usage).
     * </p>
     *
     * @param accessToken
     *         An access token to validate.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The access token is invalid. To be concrete, the access
     *         token does not exist or it has expired.
     */
    public AccessTokenInfo validate(String accessToken) throws WebApplicationException
    {
        return validate(accessToken, null, null, null, null, null, null);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validate(String, String[], String)
     * validate}<code>(accessToken, requiredScopes, null)</code>.
     *
     * </p>
     * When the given access token is not valid, this method throws a
     * {@link WebApplicationException}. The response contained in the
     * exception complies with the requirements described in <a href=
     * "http://tools.ietf.org/html/rfc6750">RFC 6750</a> (The OAuth
     * 2.0 Authorization Framework: Bearer Token Usage).
     * </p>
     *
     * @param accessToken
     *         An access token to validate.
     *
     * @param requiredScopes
     *         Scopes that must be associated with the access token.
     *         {@code null} is okay.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The access token is invalid. To be concrete, one or more of
     *         the following conditions meet.
     *         <ol>
     *           <li>The access token does not exist.
     *           <li>The access token has expired.
     *           <li>The access token does not cover the required scopes.
     *         </ol>
     */
    public AccessTokenInfo validate(String accessToken, String[] requiredScopes) throws WebApplicationException
    {
        return validate(accessToken, requiredScopes, null, null, null, null, null);
    }


    /**
     * Validate an access token.
     *
     * </p>
     * When the given access token is not valid, this method throws a
     * {@link WebApplicationException}. The response contained in the
     * exception complies with the requirements described in <a href=
     * "http://tools.ietf.org/html/rfc6750">RFC 6750</a> (The OAuth
     * 2.0 Authorization Framework: Bearer Token Usage).
     * </p>
     *
     * @param accessToken
     *         An access token to validate.
     *
     * @param requiredScopes
     *         Scopes that must be associated with the access token.
     *         {@code null} is okay.
     *
     * @param requiredSubject
     *         Subject (= user's unique identifier) that must be associated
     *         with the access token. {@code null} is okay.
     *
     * @param clientCertificate
     *         TLS Certificate of the client presented during a call to
     *         the resource server, used with TLS-bound access tokens.
     *         Can be {@code null} if no certificate is presented.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The access token is invalid. To be concrete, one or more of
     *         the following conditions meet.
     *         <ol>
     *           <li>The access token does not exist.
     *           <li>The access token has expired.
     *           <li>The access token does not cover the required scopes.
     *           <li>The access token is not associated with the required subject.
     *         </ol>
     */
    public AccessTokenInfo validate(
            String accessToken, String[] requiredScopes, String requiredSubject, String clientCertificate) throws WebApplicationException
    {
        return validate(accessToken, requiredScopes, requiredSubject, clientCertificate, null, null, null);
    }


    /**
     * Validate an access token.
     *
     * </p>
     * When the given access token is not valid, this method throws a
     * {@link WebApplicationException}. The response contained in the
     * exception complies with the requirements described in <a href=
     * "http://tools.ietf.org/html/rfc6750">RFC 6750</a> (The OAuth
     * 2.0 Authorization Framework: Bearer Token Usage).
     * </p>
     *
     * @param accessToken
     *            An access token to validate.
     *
     * @param requiredScopes
     *            Scopes that must be associated with the access token.
     *            {@code null} is okay.
     *
     * @param requiredSubject
     *            Subject (= user's unique identifier) that must be associated
     *            with the access token. {@code null} is okay.
     *
     * @param clientCertificate
     *            TLS Certificate of the client presented during a call to
     *            the resource server, used with TLS-bound access tokens.
     *            Can be {@code null} if no certificate is presented.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *             The access token is invalid. To be concrete, one or more of
     *             the following conditions meet.
     *             <ol>
     *             <li>The access token does not exist.
     *             <li>The access token has expired.
     *             <li>The access token does not cover the required scopes.
     *             <li>The access token is not associated with the required subject.
     *             </ol>
     */
    public AccessTokenInfo validate(
            String accessToken, String[] requiredScopes, String requiredSubject, String clientCertificate,
            String dpopHeader, String htm, String htu) throws WebApplicationException
    {
        if (accessToken == null)
        {
            // Return "400 Bad Request".
            throw toException(Status.BAD_REQUEST, CHALLENGE_ON_MISSING_ACCESS_TOKEN);
        }

        try
        {
            return process(accessToken, requiredScopes, requiredSubject,
                    clientCertificate, dpopHeader, htm, htu);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in AccessTokenValidator", t);
        }
    }


    private AccessTokenInfo process(
            String accessToken, String[] scopes, String subject, String clientCertificate,
            String dpopHeader, String htm, String htu) throws WebApplicationException
    {
        // Call Authlete's /api/auth/introspection API.
        IntrospectionResponse response = getApiCaller().callIntrospection(accessToken, scopes, subject,
                clientCertificate, dpopHeader, htm, htu);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                throw toException(Status.INTERNAL_SERVER_ERROR, content);

            case BAD_REQUEST:
                // 400 Bad Request
                throw toException(Status.BAD_REQUEST, content);

            case UNAUTHORIZED:
                // 401 Unauthorized
                throw toException(Status.UNAUTHORIZED, content);

            case FORBIDDEN:
                // 403 Forbidden
                throw toException(Status.FORBIDDEN, content);

            case OK:
                // Return access token information.
                return new AccessTokenInfo(accessToken, response);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/userinfo", action);
        }
    }


    private WebApplicationException toException(Status status, String challenge)
    {
        Response response = ResponseUtil.bearerError(status, challenge);

        return new WebApplicationException(response);
    }
}
