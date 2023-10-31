/*
 * Copyright (C) 2016-2023 Authlete, Inc.
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
import java.util.LinkedHashMap;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.IntrospectionRequest;
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
    /**
     * Parameters passed to the {@link AccessTokenValidator#validate(Params)}
     * method.
     *
     * @since 2.27
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private String accessToken;
        private String[] requiredScopes;
        private String requiredSubject;
        private String clientCertificate;
        private String dpop;
        private String htm;
        private String htu;


        /**
         * Get the access token to validate.
         *
         * @return
         *         The access token to validate.
         */
        public String getAccessToken()
        {
            return accessToken;
        }


        /**
         * Set the access token to validate.
         *
         * <p>
         * If {@code null} is given, the {@link AccessTokenValidator#validate(Params)
         * validate} method will throw a {@link WebApplicationException}.
         * </p>
         *
         * @param accessToken
         *         The access token to validate.
         *
         * @return
         *         {@code this} object.
         */
        public Params setAccessToken(String accessToken)
        {
            this.accessToken = accessToken;

            return this;
        }


        /**
         * Get the scopes that must be associated with the access token.
         *
         * @return
         *         The scopes that must be associated with the access token.
         */
        public String[] getRequiredScopes()
        {
            return requiredScopes;
        }


        /**
         * Set the scopes that must be associated with the access token.
         *
         * <p>
         * If a non-null value is given, it will be checked whether the scopes
         * are associated with the access token.
         * </p>
         *
         * @param scopes
         *         The scopes that must be associated with the access token.
         *
         * @return
         *         {@code this} object.
         */
        public Params setRequiredScopes(String[] scopes)
        {
            this.requiredScopes = scopes;

            return this;
        }


        /**
         * Get the subject (= user's unique identifier) that must be associated
         * with the access token.
         *
         * @return
         *         The subject that must be associated with the access token.
         */
        public String getRequiredSubject()
        {
            return requiredSubject;
        }


        /**
         * Set the subject (= user's unique identifier) that must be associated
         * with the access token.
         *
         * <p>
         * If a non-null value is given, it will be checked whether the subject
         * is associated with the access token.
         * </p>
         *
         * @param subject
         *         The subject that must be associated with the access token.
         *
         * @return
         *         {@code this} object.
         */
        public Params setRequiredSubject(String subject)
        {
            this.requiredSubject = subject;

            return this;
        }


        /**
         * Get the client certificate presented during the API call to the
         * protected resource endpoint.
         *
         * @return
         *         The client certificate.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html"
         *      >RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
         */
        public String getClientCertificate()
        {
            return clientCertificate;
        }


        /**
         * Set the client certificate presented during the API call to the
         * protected resource endpoint.
         *
         * <p>
         * If the access token is bound to a client certificate, it will be
         * checked whether the presented client certificate matches the one
         * bound to the access token. See <a href=
         * "https://www.rfc-editor.org/rfc/rfc8705.html">RFC 8705</a> for
         * details.
         * </p>
         *
         * @param certificate
         *         The client certificate.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html"
         *      >RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
         */
        public Params setClientCertificate(String certificate)
        {
            this.clientCertificate = certificate;

            return this;
        }


        /**
         * Get the DPoP proof JWT (the value of the {@code DPoP} HTTP header).
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
         * If the token type of the access token is DPoP, it will be checked
         * whether the presented DPoP proof JWT is valid for the access token.
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
         * Get the HTTP method of the API call to the protected resource
         * endpoint.
         *
         * @return
         *         The HTTP method of the API call to the protected resource
         *         endpoint. For example, {@code "GET"}.
         */
        public String getHtm()
        {
            return htm;
        }


        /**
         * Set the HTTP method of the API call to the protected resource
         * endpoint.
         *
         * <p>
         * If the token type of the access token is DPoP, it will be checked
         * whether the HTTP method is valid for the presented DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htm
         *         The HTTP method of the API call to the protected resource
         *         endpoint. For example, {@code "GET"}.
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
         * Get the URL of the protected resource endpoint.
         *
         * @return
         *         The URL of the protected resource endpoint.
         */
        public String getHtu()
        {
            return htu;
        }


        /**
         * Set the URL of the protected resource endpoint.
         *
         * <p>
         * If the token type of the access token is DPoP, it will be checked
         * whether the URL is valid for the presented DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htu
         *         The URL of the protected resource endpoint.
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
     * Validate an access token. This method is an alias of the
     * {@link #validate(Params)} method.
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
        Params params = new Params()
                .setAccessToken(accessToken)
                ;

        return validate(params);
    }


    /**
     * Validate an access token. This method is an alias of the
     * {@link #validate(Params)} method.
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
    public AccessTokenInfo validate(
            String accessToken, String[] requiredScopes) throws WebApplicationException
    {
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                ;

        return validate(params);
    }


    /**
     * Validate an access token. This method is an alias of the
     * {@link #validate(Params)} method.
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
     *           <li>The access token is bound to a client certificate, but the
     *               presented one does not match.
     *         </ol>
     */
    public AccessTokenInfo validate(
            String accessToken, String[] requiredScopes,
            String requiredSubject, String clientCertificate) throws WebApplicationException
    {
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                .setRequiredSubject(requiredSubject)
                .setClientCertificate(clientCertificate)
                ;

        return validate(params);
    }


    /**
     * Validate an access token.
     *
     * @param params
     *         Parameters needed for access token validation.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The access token is invalid.
     *
     * @since 2.27
     */
    public AccessTokenInfo validate(Params params) throws WebApplicationException
    {
        if (params == null || params.getAccessToken() == null)
        {
            // Return "400 Bad Request".
            throw toException(Status.BAD_REQUEST, CHALLENGE_ON_MISSING_ACCESS_TOKEN, null);
        }

        try
        {
            return process(params);
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


    /**
     * Validate an access token.
     *
     * @param request
     *         The request parameters to Authlete's {@code /auth/introspection} API.
     *
     * @return
     *         The response from the Authlete's {@code /auth/introspection} API.
     *
     * @throws WebApplicationException
     *         The access token is invalid or something unexpected happened.
     *         This exception is raised when the {@code action} response parameter
     *         in the response from the {@code /auth/introspection} API is not
     *         {@link IntrospectionResponse.Action#OK OK}.
     *
     * @since 2.66
     */
    public IntrospectionResponse validate(IntrospectionRequest request) throws WebApplicationException
    {
        try
        {
            return process(request);
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


    private AccessTokenInfo process(Params params) throws WebApplicationException
    {
        // Call Authlete's /api/auth/introspection API.
        IntrospectionResponse response = getApiCaller().callIntrospection(
                params.getAccessToken(),
                params.getRequiredScopes(),
                params.getRequiredSubject(),
                params.getClientCertificate(),
                params.getDpop(),
                params.getHtm(),
                params.getHtu()
        );

        // Handle the response from the /auth/introspection API.
        handleIntrospectionResponse(response);

        // Simplify the introspection response to an AccessTokenInfo instance.
        return new AccessTokenInfo(params.getAccessToken(), response);
    }


    private IntrospectionResponse process(IntrospectionRequest request) throws WebApplicationException
    {
        // Call Authlete's /api/auth/introspection API.
        IntrospectionResponse response = getApiCaller().callIntrospection(request);

        // Handle the response from the /auth/introspection API.
        handleIntrospectionResponse(response);

        return response;
    }


    private void handleIntrospectionResponse(IntrospectionResponse response)
    {
        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResponseContent();

        // Additional HTTP headers.
        Map<String, Object> headers = prepareHeaders(response);

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                throw toException(Status.INTERNAL_SERVER_ERROR, content, headers);

            case BAD_REQUEST:
                // 400 Bad Request
                throw toException(Status.BAD_REQUEST, content, headers);

            case UNAUTHORIZED:
                // 401 Unauthorized
                throw toException(Status.UNAUTHORIZED, content, headers);

            case FORBIDDEN:
                // 403 Forbidden
                throw toException(Status.FORBIDDEN, content, headers);

            case OK:
                return;

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/introspection", action);
        }
    }


    private static Map<String, Object> prepareHeaders(IntrospectionResponse response)
    {
        Map<String, Object> headers = new LinkedHashMap<>();

        // DPoP-Nonce
        String dpopNonce = response.getDpopNonce();
        if (dpopNonce != null)
        {
            headers.put("DPoP-Nonce", dpopNonce);
        }

        return headers;
    }


    private WebApplicationException toException(
            Status status, String challenge, Map<String, Object> headers)
    {
        Response response = ResponseUtil.bearerError(status, challenge, headers);

        return new WebApplicationException(response);
    }
}
