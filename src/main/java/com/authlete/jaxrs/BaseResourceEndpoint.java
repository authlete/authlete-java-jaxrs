/*
 * Copyright (C) 2016-2022 Authlete, Inc.
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
     * #validateAccessToken(AuthleteApi, AccessTokenValidator.Params)}.
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
        Params params = new Params()
                .setAccessToken(accessToken)
                ;

        return validateAccessToken(api, params);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, AccessTokenValidator.Params)}.
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
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                ;

        return validateAccessToken(api, params);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, AccessTokenValidator.Params)}.
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
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                .setRequiredSubject(requiredSubject)
                ;

        return validateAccessToken(api, params);
    }


    /**
     * Validate an access token. This method is an alias of {@link
     * #validateAccessToken(AuthleteApi, AccessTokenValidator.Params)}.
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
        Params params = new Params()
                .setAccessToken(accessToken)
                .setRequiredScopes(requiredScopes)
                .setRequiredSubject(requiredSubject)
                .setClientCertificate(clientCertificate)
                ;

        return validateAccessToken(api, params);
    }


    /**
     * Validate an access token.
     *
     * <p>
     * This method internally creates an {@link AccessTokenValidator} instance
     * and calls its {@link AccessTokenValidator#validate(Params)
     * validate()} method. Then, this method uses the value returned from the
     * {@code validate()} method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code AccessTokenValidator.validate()} method raises a {@link
     * WebApplicationException}, this method calls {@link
     * #onError(WebApplicationException) onError()} method with the exception.
     * The default implementation of {@code onError()} does nothing. You can
     * override the method as necessary. After calling {@code onError()}
     * method, this method re-throws the exception. The response contained in
     * the exception complies with the requirements described in <a href=
     * "https://tools.ietf.org/html/rfc6750">RFC 6750</a> (The OAuth 2.0
     * Authorization Framework: Bearer Token Usage).
     * </p>
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
        try
        {
            // Validate the access token and obtain the information about it.
            return new AccessTokenValidator(api).validate(params);
        }
        catch (WebApplicationException e)
        {
            // The access token is invalid. (Or an network error, or some others.)
            onError(e);

            throw e;
        }
    }
}
