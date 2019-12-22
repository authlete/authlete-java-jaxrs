/*
 * Copyright (C) 2016-2019 Authlete, Inc.
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
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import com.authlete.common.assurance.constraint.ClaimsConstraint;
import com.authlete.common.assurance.constraint.VerifiedClaimConstraint;
import com.authlete.common.assurance.constraint.VerifiedClaimsConstraint;
import com.authlete.common.assurance.constraint.VerifiedClaimsContainerConstraint;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthzDetails;
import com.authlete.common.dto.AuthzDetailsElement;
import com.authlete.common.dto.AuthzDetailsElementSerializer;
import com.authlete.common.dto.AuthzDetailsSerializer;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.Pair;
import com.authlete.common.dto.Scope;
import com.authlete.common.types.User;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


/**
 * Model class to hold data which are referred to in an authorization page.
 *
 * <p>
 * Feel free to extend this class as necessary.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class AuthorizationPageModel implements Serializable
{
    private static final long serialVersionUID = 3L;


    /**
     * The name of the service.
     */
    private String serviceName;


    /**
     * The name of the client application.
     */
    private String clientName;


    /**
     * The description of the client application.
     */
    private String description;


    /**
     * The URL of the logo image of the client application.
     */
    private String logoUri;


    /**
     * The URL of the homepage of the client application.
     */
    private String clientUri;


    /**
     * The URL of the policy page of the client application.
     */
    private String policyUri;


    /**
     * The URL of "Terms of Service" page of the client application.
     */
    private String tosUri;


    /**
     * Scopes requested by the authorization request.
     */
    private Scope[] scopes;


    /**
     * The login ID that should be used as the initial value for the
     * login ID field in the authorization page.
     */
    private String loginId;


    /**
     * This variable holds {@code "readonly"} when the initial value
     * of the login ID should not be changed.
     */
    private String loginIdReadOnly;


    /**
     * Currently logged in user, could be null if no user is logged in.
     */
    private User user;


    /**
     * The content of the {@code authorization_details} request parameter
     * in JSON format. See "OAuth 2.0 Rich Authorization Requests".
     *
     * @since 2.23
     */
    private String authorizationDetails;


    /**
     * The value of the {@code purpose} request parameter.
     *
     * @since 2.25
     */
    private String purpose;


    /**
     * Purposes for verified claims for the ID token.
     *
     * @since 2.25
     */
    private Pair[] purposesForIdToken;


    /**
     * Purposes for verified claims for the userinfo.
     *
     * @since 2.25
     */
    private Pair[] purposesForUserInfo;


    /**
     * The default constructor with default values.
     */
    public AuthorizationPageModel()
    {
    }


    /**
     * Create an {@link AuthorizationPageModel} instance using information
     * contained in an {@link AuthorizationResponse} object, which represents
     * a response from Authlete's {@code /api/auth/authorization} API.
     *
     * <p>
     * {@code user} parameter was added by version 2.1.
     * </p>
     *
     * @param info
     *         An {@link AuthorizationResponse} object, which represents a
     *         response from Authlete's {@code /api/auth/authorization} API.
     *
     * @param user
     */
    public AuthorizationPageModel(AuthorizationResponse info, User user)
    {
        Client client = info.getClient();

        serviceName          = info.getService().getServiceName();
        clientName           = client.getClientName();
        description          = client.getDescription();
        logoUri              = toString(client.getLogoUri());
        clientUri            = toString(client.getClientUri());
        policyUri            = toString(client.getPolicyUri());
        tosUri               = toString(client.getTosUri());
        scopes               = info.getScopes();
        loginId              = computeLoginId(info);
        loginIdReadOnly      = computeLoginIdReadOnly(info);
        authorizationDetails = toString(info.getAuthorizationDetails());
        purpose              = info.getPurpose();
        purposesForIdToken   = convertVerifiedClaimsToPairArray(info.getIdTokenClaims());
        purposesForUserInfo  = convertVerifiedClaimsToPairArray(info.getUserInfoClaims());

        // current logged in user, could be null
        this.user = user;
    }


    /**
     * Get the name of the service.
     *
     * @return
     *         The name of the service.
     */
    public String getServiceName()
    {
        return serviceName;
    }


    /**
     * Set the name of the service.
     *
     * @param serviceName
     *         The name of the service.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setServiceName(String serviceName)
    {
        this.serviceName = serviceName;

        return this;
    }


    /**
     * Get the name of the client application.
     *
     * @return
     *         The name of the client application.
     */
    public String getClientName()
    {
        return clientName;
    }


    /**
     * Set the name of the client application.
     *
     * @param clientName
     *         The name of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setClientName(String clientName)
    {
        this.clientName = clientName;

        return this;
    }


    /**
     * Get the description of the client application.
     *
     * @return
     *         The description of the client application.
     */
    public String getDescription()
    {
        return description;
    }


    /**
     * Set the description of the client application.
     *
     * @param description
     *         The description of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setDescription(String description)
    {
        this.description = description;

        return this;
    }


    /**
     * Get the URL of the logo image of the client application.
     *
     * @return
     *         The URL of the logo image of the client application.
     */
    public String getLogoUri()
    {
        return logoUri;
    }


    /**
     * Set the URL of the logo image of the client application.
     *
     * @param logoUri
     *         The URL of the logo image of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setLogoUri(String logoUri)
    {
        this.logoUri = logoUri;

        return this;
    }


    /**
     * Get the URL of the homepage of the client application.
     *
     * @return
     *         The URL of the homepage of the client application.
     */
    public String getClientUri()
    {
        return clientUri;
    }


    /**
     * Set the URL of the homepage of the client application.
     *
     * @param clientUri
     *         The URL of the homepage of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setClientUri(String clientUri)
    {
        this.clientUri = clientUri;

        return this;
    }


    /**
     * Get the URL of the policy page of the client application.
     *
     * @return
     *         The URL of the policy page of the client application.
     */
    public String getPolicyUri()
    {
        return policyUri;
    }


    /**
     * Set the URL of the policy page of the client application.
     *
     * @param policyUri
     *         The URL of the policy page of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setPolicyUri(String policyUri)
    {
        this.policyUri = policyUri;

        return this;
    }


    /**
     * Get the URL of "Terms of Service" page of the client application.
     *
     * @return
     *         The URL of "Terms of Service" page of the client application.
     */
    public String getTosUri()
    {
        return tosUri;
    }


    /**
     * Set the URL of "Terms of Service" page of the client application.
     *
     * @param tosUri
     *         The URL of "Terms of Service" page of the client application.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setTosUri(String tosUri)
    {
        this.tosUri = tosUri;

        return this;
    }


    /**
     * Get the list of scopes requested by the authorization request.
     *
     * @return
     *         The list of requested scopes.
     */
    public Scope[] getScopes()
    {
        return scopes;
    }


    /**
     * Set the list of scopes requested by the authorization request.
     *
     * @param scopes
     *         The list of requested scopes.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setScopes(Scope[] scopes)
    {
        this.scopes = scopes;

        return this;
    }


    /**
     * Get the login ID which should be set to the login ID field
     * in the authorization page as the initial value.
     *
     * @return
     *         The initial value of the login ID.
     */
    public String getLoginId()
    {
        return loginId;
    }


    /**
     * Set the login ID which should be set to the login ID field
     * in the authorization page as the initial value.
     *
     * @param loginId
     *         The initial value of the login ID.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setLoginId(String loginId)
    {
        this.loginId = loginId;

        return this;
    }


    /**
     * Return {@code "readonly"} if the initial value of the login ID
     * should not be changed.
     *
     * @return
     *         {@code "readonly"} if the initial value of the login ID
     *         should not be changed. Otherwise, {@code null}.
     */
    public String getLoginIdReadOnly()
    {
        return loginIdReadOnly;
    }


    /**
     * Set the value returned from {@link #getLoginIdReadOnly()}.
     *
     * @param loginIdReadOnly
     *         Pass {@code "readonly"} if the initial value of the login
     *         ID should not be changed. Otherwise, pass {@code null}.
     *
     * @return
     *         {@code this} object.
     */
    public AuthorizationPageModel setLoginIdReadOnly(String loginIdReadOnly)
    {
        this.loginIdReadOnly = loginIdReadOnly;

        return this;
    }


    /**
     * Get the user.
     *
     * @return
     *         The user.
     *
     * @since 2.1
     */
    public User getUser()
    {
        return user;
    }


    /**
     * Set the user.
     *
     * @param user
     *            The user to set.
     *
     * @since 2.1
     */
    public void setUser(User user)
    {
        this.user = user;
    }


    /**
     * Get the content of the {@code authorization_details} request parameter
     * in JSON format. See "OAuth 2.0 Rich Authorization Requests" for details.
     *
     * @return
     *         Authorization details in JSON format.
     *
     * @since 2.23
     */
    public String getAuthorizationDetails()
    {
        return authorizationDetails;
    }


    /**
     * Set the content of the {@code authorization_details} request parameter
     * in JSON format. See "OAuth 2.0 Rich Authorization Requests" for details.
     *
     * @param details
     *         Authorization details in JSON format.
     *
     * @since 2.23
     */
    public void setAuthorizationDetails(String details)
    {
        this.authorizationDetails = details;
    }


    /**
     * Get the value of the {@code purpose} request parameter. See <a href=
     * "https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#rfc.section.8"
     * >OpenID Connect for Identity Assurance 1.0, Transaction-specific Purpose</a>
     * for details.
     *
     * @return
     *         The value of the {@code purpose} request parameter.
     *
     * @since 2.25
     */
    public String getPurpose()
    {
        return purpose;
    }


    /**
     * Set the value of the {@code purpose} request parameter. See <a href=
     * "https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html#rfc.section.8"
     * >OpenID Connect for Identity Assurance 1.0, Transaction-specific Purpose</a>
     * for details.
     *
     * @param purpose
     *         The value of the {@code purpose} request parameter.
     *
     * @since 2.25
     */
    public void setPurpose(String purpose)
    {
        this.purpose = purpose;
    }


    /**
     * Get the purposes of verified claims requested for an ID token.
     *
     * <p>
     * For example, when an authorization request contains a {@code claims}
     * request parameter whose content is as follow:
     * </p>
     *
     * <pre>
     * {
     *   "id_token":{
     *     "verified_claims":{
     *       "claims":{
     *         "given_name":{
     *           "essential":true,
     *           "purpose":"To make communication look more personal"
     *         },
     *         "family_name":{
     *           "essential":true
     *         },
     *         "birthdate":{
     *           "purpose":"To send you best wishes on your birthday"
     *         }
     *       }
     *     }
     *   }
     * }
     * </pre>
     *
     * , this method returns an array which contains the following elements.
     *
     * <blockquote>
     * <table border="1" cellpadding="5" style="border-collapse: collapse;">
     *   <thead>
     *     <tr bgcolor="orange">
     *       <th>Index</th>
     *       <th><code>getKey()</th>
     *       <th><code>getValue()</th>
     *     </tr>
     *   </thead>
     *   <tbody>
     *     <tr>
     *       <td align="center">0</td>
     *       <td><code>given_name</code></td>
     *       <td><code>To make communication look more personal</code></td>
     *     </tr>
     *     <tr>
     *       <td align="center">1</td>
     *       <td><code>birthdate</code></td>
     *       <td><code>To send you best wishes on your birthday</code></td>
     *     </tr>
     *   </tbody>
     * </table>
     * </blockquote>
     *
     * <p>
     * Note that the order of the elements is not assured.
     * </p>
     *
     * @return
     *         Pairs of claim name and its purpose.
     *
     * @since 2.25
     */
    public Pair[] getPurposesForIdToken()
    {
        return purposesForIdToken;
    }


    /**
     * Set the purposes of verified claims requested for an ID token.
     *
     * @param purposes
     *         Pairs of claim name and its purpose.
     *
     * @since 2.25
     */
    public void setPurposesForIdToken(Pair[] purposes)
    {
        this.purposesForIdToken = purposes;
    }


    /**
     * Get the purposes of verified claims requested for userinfo.
     *
     * <p>
     * For example, when an authorization request contains a {@code claims}
     * request parameter whose content is as follow:
     * </p>
     *
     * <pre>
     * {
     *   "userinfo":{
     *     "verified_claims":{
     *       "claims":{
     *         "given_name":{
     *           "essential":true,
     *           "purpose":"To make communication look more personal"
     *         },
     *         "family_name":{
     *           "essential":true
     *         },
     *         "birthdate":{
     *           "purpose":"To send you best wishes on your birthday"
     *         }
     *       }
     *     }
     *   }
     * }
     * </pre>
     *
     * , this method returns an array which contains the following elements.
     *
     * <blockquote>
     * <table border="1" cellpadding="5" style="border-collapse: collapse;">
     *   <thead>
     *     <tr bgcolor="orange">
     *       <th>Index</th>
     *       <th><code>getKey()</th>
     *       <th><code>getValue()</th>
     *     </tr>
     *   </thead>
     *   <tbody>
     *     <tr>
     *       <td align="center">0</td>
     *       <td><code>given_name</code></td>
     *       <td><code>To make communication look more personal</code></td>
     *     </tr>
     *     <tr>
     *       <td align="center">1</td>
     *       <td><code>birthdate</code></td>
     *       <td><code>To send you best wishes on your birthday</code></td>
     *     </tr>
     *   </tbody>
     * </table>
     * </blockquote>
     *
     * <p>
     * Note that the order of the elements is not assured.
     * </p>
     *
     * @return
     *         Pairs of claim name and its purpose.
     *
     * @since 2.25
     */
    public Pair[] getPurposesForUserInfo()
    {
        return purposesForUserInfo;
    }


    /**
     * Set the purposes of verified claims requested for userinfo.
     *
     * @param purposes
     *         Pairs of claim name and its purpose.
     *
     * @since 2.25
     */
    public void setPurposesForUserInfo(Pair[] purposes)
    {
        this.purposesForUserInfo = purposes;
    }


    /**
     * Get the string representation of the given URI.
     *
     * @param uri
     *         A URI.
     *
     * @return
     *         The string representation of the given URI. If {@code null}
     *         is given, {@code null} is returned.
     */
    private static String toString(URI uri)
    {
        return (uri == null) ? null : uri.toString();
    }


    /**
     * Compute the initial value for the login ID field in the
     * authorization page.
     */
    private static String computeLoginId(AuthorizationResponse info)
    {
        if (info.getSubject() != null)
        {
            return info.getSubject();
        }

        return info.getLoginHint();
    }


    /**
     * Return {@code "readonly"} if the authorization request requires
     * that a specific subject be used.
     */
    private static String computeLoginIdReadOnly(AuthorizationResponse info)
    {
        if (info.getSubject() != null)
        {
            return "readonly";
        }
        else
        {
            return null;
        }
    }


    private static String toString(AuthzDetails details)
    {
        if (details == null)
        {
            return null;
        }

        AuthzDetailsElement[] elements = details.getElements();

        if (elements == null || elements.length == 0)
        {
            return null;
        }

        return toJson(details);
    }


    private static String toJson(Object object)
    {
        return createGson().toJson(object);
    }


    private static Gson createGson()
    {
        return createGsonBuilder().setPrettyPrinting().create();
    }


    private static GsonBuilder createGsonBuilder()
    {
        return new GsonBuilder()
            .registerTypeAdapter(
                AuthzDetails.class, new AuthzDetailsSerializer())
            .registerTypeAdapter(
                AuthzDetailsElement.class, new AuthzDetailsElementSerializer())
            ;
    }


    private static Pair[] convertVerifiedClaimsToPairArray(String claims)
    {
        if (claims == null)
        {
            return null;
        }

        // Parse the "verified_claims" that the JSON may contain.
        VerifiedClaimsConstraint verifiedClaimsConstraint =
            VerifiedClaimsContainerConstraint
                .fromJson(claims).getVerifiedClaims();

        // If "verified_claims" is not included or its value is null.
        if (!verifiedClaimsConstraint.exists() || verifiedClaimsConstraint.isNull())
        {
            return null;
        }

        // "claims" in the "verified_claims".
        ClaimsConstraint claimsConstraint = verifiedClaimsConstraint.getClaims();

        // If "claims" is not included or its value is null.
        if (!claimsConstraint.exists() || claimsConstraint.isNull())
        {
            return null;
        }

        List<Pair> list = new ArrayList<Pair>();

        // For each requested verified claim.
        for (Map.Entry<String, VerifiedClaimConstraint> entry : claimsConstraint.entrySet())
        {
            addPurposePair(list, entry);
        }

        if (list.size() == 0)
        {
            return null;
        }

        return list.toArray(new Pair[list.size()]);
    }


    private static void addPurposePair(List<Pair> list, Map.Entry<String, VerifiedClaimConstraint> entry)
    {
        String purpose = entry.getValue().getPurpose();

        if (purpose == null || purpose.length() == 0)
        {
            return;
        }

        // Add a pair of claim name and its purpose.
        list.add(new Pair(entry.getKey(), purpose));
    }
}
