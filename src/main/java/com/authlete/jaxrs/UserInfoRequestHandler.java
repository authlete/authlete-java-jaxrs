/*
 * Copyright (C) 2016-2021 Authlete, Inc.
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
import java.util.List;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.assurance.VerifiedClaims;
import com.authlete.common.assurance.constraint.VerifiedClaimsConstraint;
import com.authlete.common.assurance.constraint.VerifiedClaimsContainerConstraint;
import com.authlete.common.dto.UserInfoResponse;
import com.authlete.common.dto.UserInfoResponse.Action;
import com.authlete.jaxrs.spi.UserInfoRequestHandlerSpi;


/**
 * Handler for userinfo requests to a <a href=
 * "http://openid.net/specs/openid-connect-core-1_0.html#UserInfo"
 * >UserInfo Endpoint</a> defined in <a href=
 * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect
 * Core 1&#x002E;0</a>.
 *
 * <p>
 * In an implementation of userinfo endpoint, call one of {@code handle()}
 * method variants and use the response as the response from the endpoint
 * to the client application. {@code handle()} method calls Authlete's
 * {@code /api/auth/userinfo} API and {@code /api/auth/userinfo/issue} API.
 * </p>
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class UserInfoRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the {@link UserInfoRequestHandler#handle(Params)}
     * method.
     *
     * @since 2.27
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private String accessToken;
        private String clientCertificate;
        private String dpop;
        private String htm;
        private String htu;


        /**
         * Get the access token included in the userinfo request.
         *
         * @return
         *         The access token.
         */
        public String getAccessToken()
        {
            return accessToken;
        }


        /**
         * Set the access token included in the userinfo request.
         *
         * @param accessToken
         *         The access token.
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
         * Get the client certificate included in the userinfo request.
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
         * Set the client certificate included in the userinfo request.
         *
         * @param clientCertificate
         *         The client certificate.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://www.rfc-editor.org/rfc/rfc8705.html"
         *      >RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens</a>
         */
        public Params setClientCertificate(String clientCertificate)
        {
            this.clientCertificate = clientCertificate;

            return this;
        }


        /**
         * Get the DPoP proof JWT (the value of the {@code DPoP} HTTP header).
         *
         * <p>
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
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
         * Get the HTTP method of the userinfo request.
         *
         * @return
         *         The HTTP method of the userinfo request.
         */
        public String getHtm()
        {
            return htm;
        }


        /**
         * Set the HTTP method of the userinfo request.
         *
         * <p>
         * The value should be either {@code "GET"} or {@code "POST"} unless
         * new specifications allowing other HTTP methods at the userinfo
         * endpoint are developed.
         * </p>
         *
         * <p>
         * The value passed here will be used to validate the DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htm
         *         The HTTP method of the userinfo request.
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
         * Get the URL of the userinfo endpoint.
         *
         * @return
         *         The URL of the userinfo endpoint.
         */
        public String getHtu()
        {
            return htu;
        }


        /**
         * Set the URL of the userinfo endpoint.
         *
         * <p>
         * If this parameter is omitted, the {@code userInfoEndpoint} property
         * of {@link Service} will be used as the default value.
         * </p>
         *
         * <p>
         * The value passed here will be used to validate the DPoP proof JWT.
         * See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the
         * Application Layer (DPoP)"</i> for details.
         * </p>
         *
         * @param htu
         *         The URL of the userinfo endpoint.
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
        = "Bearer error=\"invalid_token\",error_description=\""
        + "An access token must be sent as a Bearer Token. "
        + "See OpenID Connect Core 1.0, 5.3.1. UserInfo Request for details.\"";


    /**
     * Implementation of {@link UserInfoRequestHandlerSpi} interface.
     */
    private final UserInfoRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link UserInfoRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link UserInfoRequestHandlerSpi} interface.
     */
    public UserInfoRequestHandler(AuthleteApi api, UserInfoRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle a userinfo request to a <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#UserInfo"
     * >UserInfo Endpoint</a> defined in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect
     * Core 1&#x002E;0</a>.
     *
     * @param accessToken
     *         An access token.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(String accessToken) throws WebApplicationException
    {
        Params params = new Params()
                .setAccessToken(accessToken)
                ;

        return handle(params);
    }


    /**
     * Handle a userinfo request.
     *
     * @param params
     *         Parameters needed to handle the userinfo request.
     *
     * @return
     *         A response that should be returned from the endpoint to the
     *         client application.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(Params params) throws WebApplicationException
    {
        // If an access token is not available.
        if (params == null || params.getAccessToken() == null)
        {
            // Return "400 Bad Request".
            return ResponseUtil.bearerError(
                    Status.BAD_REQUEST, CHALLENGE_ON_MISSING_ACCESS_TOKEN);
        }

        try
        {
            // Process the userinfo request.
            return process(params);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in UserInfoRequestHandler", t);
        }
    }


    /**
     * Process the userinfo request with the access token.
     */
    private Response process(Params params)
    {
        // Call Authlete's /api/auth/userinfo API.
        UserInfoResponse response = getApiCaller().callUserInfo(
                params.getAccessToken(),
                params.getClientCertificate(),
                params.getDpop(),
                params.getHtm(),
                params.getHtu()
        );

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

            case OK:
                // Return the user information.
                return getUserInfo(response);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/userinfo", action);
        }
    }


    /**
     * Generate a JSON or a JWT containing user information by calling
     * Authlete's {@code /api/auth/userinfo/issue} API.
     */
    private Response getUserInfo(UserInfoResponse response)
    {
        String subject = response.getSubject();

        // Collect claim values of the user.
        Map<String, Object> claims = collectClaims(subject, response.getClaims());

        // Collect claim data that are referenced when Authlete computes
        // values of transformed claims.
        Map<String, Object> claimsForTx =
                collectClaims(subject, response.getRequestedClaimsForTx());

        // Collect verified claims.
        // See "OpenID Connect for Identity Assurance 1.0" for details.
        claims = collectVerifiedClaims(claims, subject, response.getUserInfoClaims());

        try
        {
            // Generate a JSON or a JWT containing user information
            // by calling Authlete's /api/auth/userinfo/issue API.
            return getApiCaller().userInfoIssue(
                    response.getToken(), claims, claimsForTx);
        }
        catch (WebApplicationException e)
        {
            return e.getResponse();
        }
    }


    private Map<String, Object> collectClaims(String subject, String[] claimNames)
    {
        // If no claim is required.
        if (claimNames == null || claimNames.length == 0)
        {
            return null;
        }

        // Let the implementation of UserInfoRequestHandlerSpi prepare
        // claims of the user who is identified by the subject.
        mSpi.prepareUserClaims(subject, claimNames);

        // Claim values.
        Map<String, Object> claims = new LinkedHashMap<String, Object>();

        // For each requested claim.
        for (String claimName : claimNames)
        {
            // If the claim name is empty.
            if (claimName == null || claimName.length() == 0)
            {
                continue;
            }

            // Split the claim name into the name part and the tag part.
            String[] elements = claimName.split("#", 2);
            String name = elements[0];
            String tag  = (elements.length == 2) ? elements[1] : null;

            // If the name part is empty.
            if (name == null || name.length() == 0)
            {
                continue;
            }

            // Get the claim value of the claim.
            Object value = mSpi.getUserClaim(name, tag);

            // If the claim value was not obtained.
            if (value == null)
            {
                continue;
            }

            if (tag == null)
            {
                // Just for an edge case where claimName ends with "#".
                claimName = name;
            }

            // Add the pair of the claim name and the claim value.
            claims.put(claimName, value);
        }

        // If no claim value has been obtained.
        if (claims.size() == 0)
        {
            return null;
        }

        // Obtained claim values.
        return claims;
    }


    private Map<String, Object> collectVerifiedClaims(
            Map<String, Object> claims, String subject, String userInfoClaims)
    {
        // If the "claims" parameter in the authorization request has not
        // contained a "userinfo" property.
        if (userInfoClaims == null || userInfoClaims.length() == 0)
        {
            // No need to collect verified claims.
            return claims;
        }

        // The "userinfo" property may contain a "verified_claims" property.
        // Extract the "verified_claims".
        VerifiedClaimsConstraint constraint =
                VerifiedClaimsContainerConstraint
                    .fromJson(userInfoClaims).getVerifiedClaims();

        // If "verified_claims" is not included or its value is null.
        if (!constraint.exists() || constraint.isNull())
        {
            // No need to collect verified claims.
            return claims;
        }

        // Collect verified claims.
        List<VerifiedClaims> verifiedClaims = mSpi.getVerifiedClaims(subject, constraint);

        // Embed the verified claims as "verified_claims".
        return embedVerifiedClaims(claims, verifiedClaims);
    }


    private static Map<String, Object> embedVerifiedClaims(
            Map<String, Object> claims, List<VerifiedClaims> verifiedClaims)
    {
        // If no verified claims are provided.
        if (verifiedClaims == null || verifiedClaims.size() == 0)
        {
            return claims;
        }

        if (claims == null)
        {
            claims = new LinkedHashMap<String, Object>();
        }

        if (verifiedClaims.size() == 1)
        {
            claims.put("verified_claims", verifiedClaims.get(0));
        }
        else
        {
            claims.put("verified_claims", verifiedClaims);
        }

        return claims;
    }
}
