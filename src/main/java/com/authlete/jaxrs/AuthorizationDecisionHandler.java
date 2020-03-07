/*
 * Copyright (C) 2015-2020 Authlete, Inc.
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.assurance.VerifiedClaims;
import com.authlete.common.assurance.constraint.VerifiedClaimsConstraint;
import com.authlete.common.assurance.constraint.VerifiedClaimsContainerConstraint;
import com.authlete.common.dto.AuthorizationFailRequest.Reason;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Property;
import com.authlete.jaxrs.spi.AuthorizationDecisionHandlerSpi;


/**
 * Handler for end-user's decision on the authorization request.
 *
 * <p>
 * An authorization endpoint returns an authorization page (HTML) to an end-user,
 * and the end-user will select either "authorize" or "deny" the authorization
 * request. This class handles the decision and calls Authlete's
 * {@code /api/auth/authorization/issue} API or {@code /api/auth/authorization/fail}
 * API accordingly.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class AuthorizationDecisionHandler extends BaseHandler
{
    /**
     * Parameters for this handler.
     *
     * @since 2.25
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private String ticket;
        private String[] claimNames;
        private String[] claimLocales;
        private String idTokenClaims;


        /**
         * Get the ticket that was issued by Authlete's
         * {@code /api/auth/authorization} API.
         *
         * @return
         *         The ticket that was issued by Authlete's
         *         {@code /api/auth/authorization} API.
         */
        public String getTicket()
        {
            return ticket;
        }


        /**
         * Set the ticket that was issued by Authlete's
         * {@code /api/auth/authorization} API.
         *
         * @param ticket
         *         The ticket that was issued by Authlete's
         *         {@code /api/auth/authorization} API.
         *
         * @return
         *         {@code this} object.
         */
        public Params setTicket(String ticket)
        {
            this.ticket = ticket;

            return this;
        }


        /**
         * Get the names of requested claims.
         *
         * @return
         *         The names of requested claims.
         */
        public String[] getClaimNames()
        {
            return claimNames;
        }


        /**
         * Set the names of requested claims. The value given to this method
         * should be the value of the {@code claims} parameter in a response
         * from Authlete's {@code /api/auth/authorization} API.
         *
         * @param names
         *         The names of requested claims.
         *
         * @return
         *         {@code this} object.
         */
        public Params setClaimNames(String[] names)
        {
            this.claimNames = names;

            return this;
        }


        /**
         * Get the requested claim locales.
         *
         * @return
         *         Requested claim locales.
         */
        public String[] getClaimLocales()
        {
            return this.claimLocales;
        }


        /**
         * Set the requested claim locales. The value given to this method
         * should be the value of the {@code claimsLocales} parameter in a
         * response from Authlete's {@code /api/auth/authorization} API.
         *
         * @param locales
         *         Requested claim locales.
         *
         * @return
         *         {@code this} object.
         */
        public Params setClaimLocales(String[] locales)
        {
            this.claimLocales = locales;

            return this;
        }


        /**
         * Get the value of the {@code id_token} property in the {@code claims}
         * request parameter.
         *
         * @return
         *         Claims requested for an ID token.
         */
        public String getIdTokenClaims()
        {
            return idTokenClaims;
        }


        /**
         * Set the value of the {@code id_token} property in the {@code claims}
         * request parameter. The value given to this method should be the
         * value of the {@code idTokenClaims} parameter in a response from
         * Authlete's {@code /api/auth/authorization} API.
         *
         * @param claims
         *         Claims requested for an ID token.
         *
         * @return
         *         {@code this} object.
         */
        public Params setIdTokenClaims(String claims)
        {
            this.idTokenClaims = claims;

            return this;
        }


        /**
         * Create a {@link Params} instance from an instance of
         * {@link AuthorizationResponse}.
         *
         * @param response
         *         An response from Authlete's {@code /api/auth/authorization} API.
         *
         * @return
         *         A new {@code Params} instance built from the response.
         */
        public static Params from(AuthorizationResponse response)
        {
            return new Params()
                    .setTicket(response.getTicket())
                    .setClaimNames(response.getClaims())
                    .setClaimLocales(response.getClaimsLocales())
                    .setIdTokenClaims(response.getIdTokenClaims())
                    ;
        }
    }


    /**
     * Implementation of {@link AuthorizationDecisionHandlerSpi} interface.
     */
    private final AuthorizationDecisionHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link AuthorizationDecisionHandlerSpi}
     * interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link AuthorizationDecisionHandlerSpi} interface.
     */
    public AuthorizationDecisionHandler(AuthleteApi api, AuthorizationDecisionHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle an end-user's decision on an authorization request.
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/auth/authorization} API.
     *
     * @param claimNames
     *         Names of requested claims. Use the value of the {@code claims}
     *         parameter in a response from Authlete's {@code /api/auth/authorization} API.
     *
     * @param claimLocales
     *         Requested claim locales. Use the value of the {@code claimsLocales}
     *         parameter in a response from Authlete's {@code /api/auth/authorization} API.
     *
     * @return
     *         A response to the client application. Basically, the response
     *         will trigger redirection to the client's redirection endpoint.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(String ticket, String[] claimNames, String[] claimLocales) throws WebApplicationException
    {
        Params params = new Params()
                .setTicket(ticket)
                .setClaimNames(claimNames)
                .setClaimLocales(claimLocales)
                ;

        return handle(params);
    }


    /**
     * Handle an end-user's decision on an authorization request.
     *
     * @param params
     *         Parameters necessary to handle the decision.
     *
     * @return
     *         A response to the client application. Basically, the response
     *         will trigger redirection to the client's redirection endpoint.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.25
     */
    public Response handle(Params params) throws WebApplicationException
    {
        try
        {
            // Process the end-user's decision.
            return process(params);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in AuthorizationDecisionHandler", t);
        }
    }


    /**
     * Process the end-user's decision.
     */
    private Response process(Params params)
    {
        // If the end-user did not grant authorization to the client application.
        if (mSpi.isClientAuthorized() == false)
        {
            // The end-user denied the authorization request.
            return fail(params.getTicket(), Reason.DENIED);
        }

        // The subject (= unique identifier) of the end-user.
        String subject = mSpi.getUserSubject();

        // If the subject of the end-user is not available.
        if (subject == null || subject.length() == 0)
        {
            // The end-user is not authenticated.
            return fail(params.getTicket(), Reason.NOT_AUTHENTICATED);
        }

        // the potentially pairwise subject of the end user
        String sub = mSpi.getSub();

        // The time when the end-user was authenticated.
        long authTime = mSpi.getUserAuthenticatedAt();

        // The ACR (Authentication Context Class Reference) of the
        // end-user authentication.
        String acr = mSpi.getAcr();

        // Collect claim values.
        Map<String, Object> claims = collectClaims(
                subject, params.getClaimNames(), params.getClaimLocales());

        // Collect verified claims.
        // See "OpenID Connect for Identity Assurance 1.0" for details.
        claims = collectVerifiedClaims(claims, subject, params.getIdTokenClaims());

        // Extra properties to associate with an access token and/or
        // an authorization code.
        Property[] properties = mSpi.getProperties();

        // Scopes to associate with an access token and/or an authorization code.
        // If a non-null value is returned from mSpi.getScopes(), the scope set
        // replaces the scopes that have been specified in the original
        // authorization request.
        String[] scopes = mSpi.getScopes();

        // Authorize the authorization request.
        return authorize(params.getTicket(), subject, authTime, acr, claims, properties, scopes, sub);
    }


    /**
     * Collect claims of the end-user.
     */
    private Map<String, Object> collectClaims(String subject, String[] claimNames, String[] claimLocales)
    {
        // If no claim is required.
        if (claimNames == null || claimNames.length == 0)
        {
            return null;
        }

        // Drop empty and duplicate entries from claimLocales.
        claimLocales = normalizeClaimLocales(claimLocales);

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
            Object value = getClaim(name, tag, claimLocales);

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


    private String[] normalizeClaimLocales(String[] claimLocales)
    {
        if (claimLocales == null || claimLocales.length == 0)
        {
            return null;
        }

        // From 5.2. Claims Languages and Scripts in OpenID Connect Core 1.0
        //
        //     However, since BCP47 language tag values are case insensitive,
        //     implementations SHOULD interpret the language tag values
        //     supplied in a case insensitive manner.
        //
        Set<String> set = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

        // Normalized list.
        List<String> list = new ArrayList<String>();

        // Loop to drop empty and duplicate claim locales.
        for (String claimLocale : claimLocales)
        {
            // If the claim locale is empty.
            if (claimLocale == null || claimLocale.length() == 0)
            {
                continue;
            }

            // If the claim locale is a duplicate.
            if (set.contains(claimLocale))
            {
                continue;
            }

            set.add(claimLocale);
            list.add(claimLocale);
        }

        int size = list.size();

        if (size == 0)
        {
            return null;
        }
        else if (size == claimLocales.length)
        {
            // No change.
            return claimLocales;
        }

        // Convert the list to an array.
        String[] array = new String[size];
        list.toArray(array);

        return array;
    }


    private Object getClaim(String name, String tag, String[] claimLocales)
    {
        // If a language tag is explicitly appended.
        if (tag != null && tag.length() != 0)
        {
            // Get the claim value of the claim with the specific language tag.
            return mSpi.getUserClaim(name, tag);
        }

        // If claim locales are not specified by 'claims_locales' request parameter.
        if (claimLocales == null || claimLocales.length == 0)
        {
            // Get the claim value of the claim without any language tag.
            return mSpi.getUserClaim(name, null);
        }

        // For each claim locale. They are ordered by preference.
        for (String claimLocale : claimLocales)
        {
            // Try to get the claim value with the claim locale.
            Object value = mSpi.getUserClaim(name, claimLocale);

            // If the claim value was obtained.
            if (value != null)
            {
                return value;
            }
        }

        // The last resort. Try to get the claim value without any language tag.
        return mSpi.getUserClaim(name, null);
    }


    private Map<String, Object> collectVerifiedClaims(
            Map<String, Object> claims, String subject, String idTokenClaims)
    {
        // If the "claims" parameter does not contain an "id_token" property.
        if (idTokenClaims == null || idTokenClaims.length() == 0)
        {
            // No need to collect verified claims.
            return claims;
        }

        // The "id_token" property may contain a "verified_claims" property.
        // Extract the "verified_claims".
        VerifiedClaimsConstraint constraint =
                VerifiedClaimsContainerConstraint
                    .fromJson(idTokenClaims).getVerifiedClaims();

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


    /**
     * Handle an end-user's decision of granting authorization to the client
     * application. This method calls Authlete's {@code
     * /api/auth/authorization/issue} API.
     *
     * <p>
     * <b>Note about the {@code claims} argument:</b>
     * </p>
     *
     * <p>
     * A response from Authlete's {@code /api/auth/authorization} API contains
     * {@code claims} parameter which is a {@code String} array of claim names
     * such as {@code name}, {@code email} and {@code birthdate}. They are
     * claims requested by the client application. You are expected to collect
     * values of the claims and pass the collected claim key-value pairs to
     * Authlete's {@code /api/auth/authorization/issue} API. The {@code claims}
     * argument of this method is the collected claim key-value pairs.
     * </p>
     *
     * <p>
     * Types of claim values vary depending on claim keys. Types of most
     * standard claims (see "<a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims"
     * >5.1. Standard Claims</a>" in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect
     * Core 1.0</a>) are string, but types of {@code email_verified} claim
     * and {@code phone_number_verified} claim are boolean and the type of
     * {@code updated_at} claim is number. In addition, the type of {@code
     * address} claim is JSON object. The detailed format of {@code address}
     * claim is described in <a href=
     * "http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim"
     * >5.1.1. Address Claim</a>. {@link com.authlete.common.dto.Address
     * Address} class in <a href="https://github.com/authlete/authlete-java-common"
     * >authlete-java-common</a> library can be used to represent a value of
     * {@code address} claim.
     * </p>
     *
     * <p>
     * The following code is an example to prepare {@code claims} argument.
     * </p>
     *
     * <blockquote>
     * <pre style="border: 1px solid gray; padding: 0.5em; margin: 1em;">
     * Map&lt;String, Object&gt; claims = new HashMap&lt;String, Object&gt;();
     *
     * <span style="color: green;">// Name</span>
     * claims.put(<span style="color: darkred;">"name"</span>,        <span style="color: darkred;">"Takahiko Kawasaki"</span>);
     * claims.put(<span style="color: darkred;">"given_name"</span>,  <span style="color: darkred;">"Takahiko"</span>);
     * claims.put(<span style="color: darkred;">"family_name"</span>, <span style="color: darkred;">"Kawasaki"</span>);
     *
     * <span style="color: green;">// Name with a language tag.
     * // See <a href="http://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts"
     * >5.2. Claims Languages and Scripts</a> for details.</span>
     * claims.put(<span style="color: darkred;">"name#ja"</span>,        <span style="color: darkred;"
     * >"\u5DDD\u5D0E \u8CB4\u5F66"</span>);  <span style="color: green;">// &#x5ddd;&#x5D0E; &#x8CB4;&#x5F66;</span>
     * claims.put(<span style="color: darkred;">"given_name#ja"</span>,  <span style="color: darkred;"
     * >"\u8CB4\u5F66"</span>);               <span style="color: green;">// &#x8CB4;&#x5F66;</span>
     * claims.put(<span style="color: darkred;">"family_name#ja"</span>, <span style="color: darkred;"
     * >"\u5DDD\u5D0E"</span>);               <span style="color: green;">// &#x5ddd;&#x5D0E;</span>
     *
     * <span style="color: green;">// Postal address.
     * // See <a href="http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim"
     * >5.1.1. Address Claim</a> for details.</span>
     * Address address = new Address()
     *     .setCountry(<span style="color: darkred;">"JP"</span>)
     *     .setRegion(<span style="color: darkred;">"Tokyo"</span>)
     *     .setLocality(<span style="color: darkred;">"Itabashi-ku"</span>)
     *     .setFormatted(<span style="color: darkred;">"Itabashi-ku, Tokyo, Japan"</span>);
     * claims.put(<span style="color: darkred;">"address"</span>, address);
     *
     * <span style="color: green;">// Other information.</span>
     * claims.put(<span style="color: darkred;">"gender"</span>,    <span style="color: darkred;">"male"</span>);
     * claims.put(<span style="color: darkred;">"birthdate"</span>, <span style="color: darkred;">"1974-05-06"</span>);
     * claims.put(<span style="color: darkred;">"zoneinfo"</span>,  <span style="color: darkred;">"Asia/Tokyo"</span>);
     * claims.put(<span style="color: darkred;">"locale"</span>,    <span style="color: darkred;">"ja"</span>);
     *
     * <span style="color: green;">// FYI: Constant values in {@link com.authlete.common.types.StandardClaims
     * StandardClaims} class can be used as keys.</span></pre>
     * </blockquote>
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/auth/authorization} API.
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
     *         Extra properties to associate with an access token and/or
     *         an authorization code.
     *
     * @param scopes
     *         Scopes to associate with an access token and/or an authorization
     *         code. If {@code null} is given, the scopes contained in the
     *         original authorization request are used. Otherwise, including
     *         the case of an empty array, the scopes given to this method
     *         replace the scopes. Note that <code>"openid"</code> scope is
     *         ignored if it is not included in the original authorization
     *         request.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    private Response authorize(
            String ticket, String subject, long authTime, String acr,
            Map<String, Object> claims, Property[] properties, String[] scopes, String sub)
    {
        try
        {
            // Generate a redirect response containing an authorization code,
            // an access token and/or an ID token. If the original authorization
            // request had response_type=none, no tokens will be contained in
            // the generated response, though.
            return getApiCaller().authorizationIssue(
                    ticket, subject, authTime, acr, claims, properties, scopes, sub);
        }
        catch (WebApplicationException e)
        {
            return e.getResponse();
        }
    }


    /**
     * Generate an error response to indicate that the authorization
     * request failed. This method calls Authlete's {@code
     * /api/auth/authorization/fail} API and generates a response that
     * triggers redirection.
     * </p>
     *
     * @param ticket
     *         A ticket that was issued by Authlete's {@code /api/auth/authorization} API.
     *
     * @param reason
     *         A reason of the failure of the authorization request.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    private Response fail(String ticket, Reason reason)
    {
        try
        {
            // Generate an error response to indicate that
            // the authorization request failed.
            return getApiCaller().authorizationFail(ticket, reason).getResponse();
        }
        catch (WebApplicationException e)
        {
            return e.getResponse();
        }
    }
}
