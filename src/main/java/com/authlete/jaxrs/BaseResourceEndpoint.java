/*
 * Copyright (C) 2016-2025 Authlete, Inc.
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
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.Options;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.web.BearerToken;
import com.authlete.common.web.DpopToken;
import com.authlete.jaxrs.AccessTokenValidator.Params;


/**
 * A base class for protected resource endpoints.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class BaseResourceEndpoint extends BaseEndpoint
{
    /**
     * Extract an access token from either {@code Authorization} header
     * or request parameters.
     *
     * <p>
     * The first argument expects a value of {@code Authorization} header
     * that complies with <a href="http://tools.ietf.org/html/rfc6750"
     * >RFC 6750</a> (Bearer Token Usage). If the argument contains an
     * access token, this method returns the access token without checking
     * the second argument.
     * </p>
     *
     * <p>
     * The second argument expects a value of {@code access_token}
     * request parameter. The value of this argument is returned when
     * the first argument does not contain an access token.
     * </p>
     *
     * @param authorization
     *         A value of {@code Authorization} header whose scheme is
     *         Bearer or DPoP. For example, {@code "Bearer SlAV32hkKG"}.
     *
     * @param accessTokenInRequestParameters
     *         A value of {@code access_token} request parameter.
     *
     * @return
     *         An access token.
     */
    public String extractAccessToken(String authorization, String accessTokenInRequestParameters)
    {
        // Extract a DPoP access token from the value of Authorization header.
        String accessToken = DpopToken.parse(authorization);

        if (accessToken == null)
        {
            // if a DPoP token wasn't found, look for a Bearer in the authorization header
            accessToken = BearerToken.parse(authorization);
        }

        // If an access token was not found in Authorization header.
        if (accessToken == null)
        {
            // Use the value given via 'access_token' request parameter.
            accessToken = accessTokenInRequestParameters;
        }

        return accessToken;
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, Options) validateAccessToken}{@code
     * (api, accessToken, (Options)null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken) throws WebApplicationException
    {
        return validateAccessToken(api, accessToken, (Options)null);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], Options) validateAccessToken}{@code
     * (api, accessToken, null, options)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param accessToken
     *         An access token to validate.
     *
     * @param options
     *         The request options for the {@code /api/auth/introspection} API.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The access token is invalid. To be concrete, the access
     *         token does not exist or it has expired.
     *
     * @since 2.82
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken, Options options) throws WebApplicationException
    {
        return validateAccessToken(api, accessToken, null, options);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], Options) validateAccessToken}{@code
     * (api, accessToken, requiredScopes, (Options)null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken, String[] requiredScopes) throws WebApplicationException
    {
        return validateAccessToken(api, accessToken, requiredScopes, (Options)null);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], String, Options)
     * validateAccessToken}{@code (api, accessToken, requiredScopes, null, options)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param accessToken
     *         An access token to validate.
     *
     * @param requiredScopes
     *         Scopes that must be associated with the access token.
     *         {@code null} is okay.
     *
     * @param options
     *         The request options for the {@code /api/auth/introspection} API.
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
     *
     * @since 2.82
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken, String[] requiredScopes, Options options)
                    throws WebApplicationException
    {
        return validateAccessToken(api, accessToken, requiredScopes, null, options);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], String, Options)
     * validateAccessToken}{@code (api, accessToken, requiredScopes, requiredSubject, (Options)null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken,
            String[] requiredScopes, String requiredSubject) throws WebApplicationException
    {
        return validateAccessToken(
                api, accessToken, requiredScopes, requiredSubject, (Options)null);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], String, String, Options)
     * validateAccessToken}{@code (api, accessToken, requiredScopes, requiredSubject, null, null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
     * @param options
     *         The request options for the {@code /api/auth/introspection} API.
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
     *
     * @since 2.82
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken,
            String[] requiredScopes, String requiredSubject, Options options) throws WebApplicationException
    {
        return validateAccessToken(
                api, accessToken, requiredScopes, requiredSubject, null, null);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, String, String[], String, String, Options)
     * validateAccessToken}{@code (api, accessToken, requiredScopes, requiredSubject, clientCertificate, null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
     *               given one does not match.
     *         </ol>
     *
     * @since 2.8
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken, String[] requiredScopes,
            String requiredSubject, String clientCertificate) throws WebApplicationException
    {
        return validateAccessToken(
                api, accessToken, requiredScopes, requiredSubject, clientCertificate, null);
    }


    /**
     * Validate an access token. This method is an alias of the {@link
     * #validateAccessToken(AuthleteApi, AccessTokenValidator.Params)} method.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
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
     * @param options
     *         The request options for the {@code /api/auth/introspection} API.
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
     *               given one does not match.
     *         </ol>
     *
     * @since 2.82
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, String accessToken, String[] requiredScopes,
            String requiredSubject, String clientCertificate, Options options) throws WebApplicationException
    {
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                .setRequiredSubject(requiredSubject)
                .setClientCertificate(clientCertificate)
                ;

        return validateAccessToken(api, params, options);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, Params, Options) validateAccessToken}{@code
     * (api, params, null)}.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param params
     *         Parameters needed for access token validation.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The Access Token is invalid.
     *
     * @since 2.27
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, Params params) throws WebApplicationException
    {
        return validateAccessToken(api, params, null);
    }


    /**
     * Validate an access token.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param params
     *         Parameters needed for access token validation.
     *
     * @param options
     *         The request options for the {@code /api/auth/introspection} API.
     *
     * @return
     *         Information about the access token.
     *
     * @throws WebApplicationException
     *         The Access Token is invalid.
     *
     * @since 2.82
     */
    public AccessTokenInfo validateAccessToken(
            AuthleteApi api, Params params, Options options) throws WebApplicationException
    {
        try
        {
            // Validate the access token and obtain the information about it.
            return new AccessTokenValidator(api).validate(params, options);
        }
        catch (WebApplicationException e)
        {
            // The access token is invalid. (Or an network error, or some others.)
            onError(e);

            throw e;
        }
    }


    public IntrospectionResponse validateAccessToken(
            AuthleteApi api, IntrospectionRequest request) throws WebApplicationException
    {
        return validateAccessToken(api, request, null);
    }


    public IntrospectionResponse validateAccessToken(
            AuthleteApi api, IntrospectionRequest request, Options options) throws WebApplicationException
    {
        try
        {
            // Validate the access token and obtain the information about it.
            return new AccessTokenValidator(api).validate(request, options);
        }
        catch (WebApplicationException e)
        {
            // The access token is invalid. (Or an network error, or some others.)
            onError(e);

            throw e;
        }
    }
}
