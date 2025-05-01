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
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
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
import com.authlete.common.dto.DynamicScope;
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
    private static final long serialVersionUID = 5L;


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
     * Verified claims requested for the ID token.
     *
     * @since 2.26
     */
    private Pair[] verifiedClaimsForIdToken;


    /**
     * Flag indicating whether the authorization request requests
     * all possible verified claims for the ID token.
     *
     * @since 2.26
     */
    private boolean allVerifiedClaimsForIdTokenRequested;


    /**
     * Verified claims requested for the userinfo.
     *
     * @since 2.26
     */
    private Pair[] verifiedClaimsForUserInfo;


    /**
     * Flag indicating whether the authorization request requests
     * all possible verified claims for the userinfo.
     *
     * @since 2.26
     */
    private boolean allVerifiedClaimsForUserInfoRequested;


    /**
     * Flag indicating whether behaviors for Identity Assurance are
     * required.
     *
     * @since 2.26
     */
    private boolean identityAssuranceRequired;


    /**
     * Flag indicating whether this class assumes that the old format of
     * {@code "verified_claims"} is used. "Old" here means the 2nd
     * Implementer's Draft of OpenID Connect for Identity Assurance 1.0.
     *
     * @since 2.42
     */
    private boolean oldIdaFormatUsed;


    /**
     * Claims that the client application requests to be embedded in
     * the ID token.
     *
     * @since 2.56
     */
    private String[] claimsForIdToken;


    /**
     * Claims that the client application requests to be embedded in
     * userinfo responses.
     *
     * @since 2.56
     */
    private String[] claimsForUserInfo;


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
        scopes               = computeScopes(info);
        loginId              = computeLoginId(info);
        loginIdReadOnly      = computeLoginIdReadOnly(info);
        authorizationDetails = toString(info.getAuthorizationDetails());
        this.user            = user;

        // For "OpenID Connect for Identity Assurance 1.0"
        setupIdentityAssurance(info);

        // Requested normal claims.
        claimsForIdToken  = info.getClaims();
        claimsForUserInfo = info.getClaimsAtUserInfo();
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
     * Get the verified claims requested for the ID token.
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
     *       <th><code>getKey()</code></th>
     *       <th><code>getValue()</code></th>
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
     *       <td><code>family_name</code></td>
     *       <td></td>
     *     </tr>
     *     <tr>
     *       <td align="center">2</td>
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
     *         Requested verified claims.
     *
     * @since 2.26
     */
    public Pair[] getVerifiedClaimsForIdToken()
    {
        return verifiedClaimsForIdToken;
    }


    /**
     * Set the verified claims requested for the ID token.
     *
     * @param verifiedClaims
     *         Requested verified claims.
     *
     * @since 2.26
     */
    public void setVerifiedClaimsForIdToken(Pair[] verifiedClaims)
    {
        this.verifiedClaimsForIdToken = verifiedClaims;
    }


    /**
     * Get the flag indicating whether the authorization request requests
     * all possible verified claims for the ID token.
     *
     * <p>
     * NOTE: In the version 1.0 of "OpenID Connect for Identity Assurance",
     * {@code "claims":null} means <i>"a request for all possible Claims"</i>.
     * However, this requirement will be dropped from the future version.
     * Therefore, this method should not be used in the future.
     * The relevant discussion can be found in <a href=
     * "https://bitbucket.org/openid/ekyc-ida/issues/1142">Issue 1142</a>.
     * </p>
     *
     * @return
     *       {@code true} if the authorization request requests all possible
     *       verified claims for the ID token.
     *
     * @since 2.26
     */
    public boolean isAllVerifiedClaimsForIdTokenRequested()
    {
        return allVerifiedClaimsForIdTokenRequested;
    }


    /**
     * Set the flag indicating whether the authorization request requests
     * all possible verified claims for the ID token.
     *
     * @param requested
     *       {@code true} to indicate that the authorization request requests
     *       all possible verified claims for the ID token.
     *
     * @since 2.26
     */
    public void setAllVerifiedClaimsForIdTokenRequested(boolean requested)
    {
        this.allVerifiedClaimsForIdTokenRequested = requested;
    }


    /**
     * Get the verified claims requested for the userinfo.
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
     *       <th><code>getKey()</code></th>
     *       <th><code>getValue()</code></th>
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
     *       <td><code>family_name</code></td>
     *       <td></td>
     *     </tr>
     *     <tr>
     *       <td align="center">2</td>
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
     * @since 2.26
     */
    public Pair[] getVerifiedClaimsForUserInfo()
    {
        return verifiedClaimsForUserInfo;
    }


    /**
     * Set the verified claims requested for the userinfo.
     *
     * @param verifiedClaims
     *         Requested verified claims.
     *
     * @since 2.26
     */
    public void setVerifiedClaimsForUserInfo(Pair[] verifiedClaims)
    {
        this.verifiedClaimsForUserInfo = verifiedClaims;
    }


    /**
     * Get the flag indicating whether the authorization request requests
     * all possible verified claims for the userinfo.
     *
     * <p>
     * NOTE: In the version 1.0 of "OpenID Connect for Identity Assurance",
     * {@code "claims":null} means <i>"a request for all possible Claims"</i>.
     * However, this requirement will be dropped from the future version.
     * Therefore, this method should not be used in the future.
     * The relevant discussion can be found in <a href=
     * "https://bitbucket.org/openid/ekyc-ida/issues/1142">Issue 1142</a>.
     * </p>
     *
     * @return
     *       {@code true} if the authorization request requests all possible
     *       verified claims for the userinfo.
     *
     * @since 2.26
     */
    public boolean isAllVerifiedClaimsForUserInfoRequested()
    {
        return allVerifiedClaimsForUserInfoRequested;
    }


    /**
     * Set the flag indicating whether the authorization request requests
     * all possible verified claims for the userinfo.
     *
     * @param requested
     *       {@code true} to indicate that the authorization request requests
     *       all possible verified claims for the userinfo.
     *
     * @since 2.26
     */
    public void setAllVerifiedClaimsForUserInfoRequested(boolean requested)
    {
        this.allVerifiedClaimsForUserInfoRequested = requested;
    }


    /**
     * Get the flag indicating whether behaviors for Identity Assurance are
     * required.
     *
     * @return
     *         {@code true} if behaviors for Identity Assurance are required.
     *
     * @since 2.26
     */
    public boolean isIdentityAssuranceRequired()
    {
        return identityAssuranceRequired;
    }


    /**
     * Get the flag indicating whether behaviors for Identity Assurance are
     * required.
     *
     * @param required
     *         {@code true} to indicate that behaviors for Identity Assurance
     *         are required.
     *
     * @since 2.26
     */
    public void setIdentityAssuranceRequired(boolean required)
    {
        this.identityAssuranceRequired = required;
    }


    /**
     * Get the flag indicating whether the old format of {@code "verified_claims"}
     * is used. "Old" here means the 2nd Implementer's Draft of OpenID Connect for
     * Identity Assurance 1.0 which was published on May 19, 2020.
     *
     * <p>
     * The Implementer's Draft 3 of OpenID Connect for Identity Assurance 1.0,
     * which was published on September 6, 2021, made many breaking changes.
     * </p>
     *
     * @return
     *         {@code true} if the old format of {@code "verified_claims"} is used.
     *
     * @since 2.42
     *
     * @see <a href="https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html"
     *      >OpenID Connect for Identity Assurance 1.0</a>
     */
    public boolean isOldIdaFormatUsed()
    {
        return oldIdaFormatUsed;
    }


    /**
     * Set the flag indicating whether the old format of {@code "verified_claims"}
     * is used. "Old" here means the 2nd Implementer's Draft of OpenID Connect for
     * Identity Assurance 1.0 which was published on May 19, 2020.
     *
     * <p>
     * The Implementer's Draft 3 of OpenID Connect for Identity Assurance 1.0,
     * which was published on September 6, 2021, made many breaking changes.
     * </p>
     *
     * @param used
     *         {@code true} to indicate that the old format of {@code "verified_claims"}
     *         is used.
     *
     * @since 2.42
     *
     * @see <a href="https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html"
     *      >OpenID Connect for Identity Assurance 1.0</a>
     */
    public void setOldIdaFormatUsed(boolean used)
    {
        this.oldIdaFormatUsed = used;
    }


    /**
     * Get the claims that the client application requests to be embedded in
     * the ID token.
     *
     * @return
     *         The claims that the client application requests to be embedded
     *         in the ID token.
     *
     * @since 2.56
     */
    public String[] getClaimsForIdToken()
    {
        return claimsForIdToken;
    }


    /**
     * Set the claims that the client application requests to be embedded in
     * the ID token.
     *
     * @param claims
     *         The claims that the client application requests to be embedded
     *         in the ID token.
     *
     * @since 2.56
     */
    public void setClaimsForIdToken(String[] claims)
    {
        this.claimsForIdToken = claims;
    }


    /**
     * Get the claims that the client application requests to be embedded in
     * userinfo responses.
     *
     * @return
     *         The claims that the client application requests to be embedded
     *         in userinfo responses.
     *
     * @since 2.56
     */
    public String[] getClaimsForUserInfo()
    {
        return claimsForUserInfo;
    }


    /**
     * Set the claims that the client application requests to be embedded in
     * userinfo responses.
     *
     * @param claims
     *         The claims that the client application requests to be embedded
     *         in userinfo responses.
     *
     * @since 2.56
     */
    public void setClaimsForUserInfo(String[] claims)
    {
        this.claimsForUserInfo = claims;
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
     * Build the list of scopes to display.
     */
    private static Scope[] computeScopes(AuthorizationResponse info)
    {
        Scope[]        scopes        = info.getScopes();
        DynamicScope[] dynamicScopes = info.getDynamicScopes();

        // If the authorization request does not contain dynamic scopes.
        if (dynamicScopes == null)
        {
            // No need to convert dynamic scopes to scopes, so the value of
            // the "scopes" response parameter are used without modification.
            return scopes;
        }

        List<Scope> list = new ArrayList<Scope>();

        if (scopes != null)
        {
            // Add all the scopes without modification.
            for (Scope s : scopes)
            {
                list.add(s);
            }
        }

        // For each dynamic scope.
        for (DynamicScope ds : dynamicScopes)
        {
            // Use the value of the dynamic scope as a scope name.
            list.add(new Scope().setName(ds.getValue()));
        }

        return list.toArray(new Scope[list.size()]);
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


    private void setupIdentityAssurance(AuthorizationResponse info)
    {
        purpose = info.getPurpose();
        setupVerifiedClaimsForIdToken(info);
        setupVerifiedClaimsForUserInfo(info);
        identityAssuranceRequired = computeIdentityAssuranceRequired();
    }


    private void setupVerifiedClaimsForIdToken(AuthorizationResponse info)
    {
        if (isOldIdaFormatUsed())
        {
            setupVerifiedClaimsForIdToken_Old(info);
            return;
        }

        // allVerifiedClaimsForIdTokenRequested is not set up here.
        //
        // The flag was prepared for a certain requirement which existed in the
        // first Implementer's Draft of OpenID Connect for Identity Assurance 1.0.
        // However, the requirement was abolished by the second draft.
        //
        // History:
        //
        //   I objected to the requirement during the review period of the first
        //   draft but my feedback was not reflected to the first draft.
        //
        //     https://bitbucket.org/openid/ekyc-ida/issues/1110

        verifiedClaimsForIdToken = extractRequestedClaims(info.getIdTokenClaims());
    }


    private void setupVerifiedClaimsForIdToken_Old(AuthorizationResponse info)
    {
        // "verified_claims" in "id_token" in the "claims" request parameter.
        VerifiedClaimsConstraint verifiedClaimsConstraint =
                extractVerifiedClaims(info.getIdTokenClaims());

        if (verifiedClaimsConstraint == null)
        {
            return;
        }

        // Flag indicating whether the authorization request requests all
        // possible verified claims for an ID token.
        allVerifiedClaimsForIdTokenRequested =
                verifiedClaimsConstraint.isAllClaimsRequested();

        if (allVerifiedClaimsForIdTokenRequested == false)
        {
            // The authorization request explicitly lists verified claims.
            // Extract the list.
            verifiedClaimsForIdToken =
                    extractRequestedClaims(verifiedClaimsConstraint);
        }
    }


    private void setupVerifiedClaimsForUserInfo(AuthorizationResponse info)
    {
        if (isOldIdaFormatUsed())
        {
            setupVerifiedClaimsForUserInfo_Old(info);
            return;
        }

        // allVerifiedClaimsForUserInfoRequested is not set up here.
        //
        // The flag was prepared for a certain requirement which existed in the
        // first Implementer's Draft of OpenID Connect for Identity Assurance 1.0.
        // However, the requirement was abolished by the second draft.
        //
        // History:
        //
        //   I objected to the requirement during the review period of the first
        //   draft but my feedback was not reflected to the first draft.
        //
        //     https://bitbucket.org/openid/ekyc-ida/issues/1110

        verifiedClaimsForUserInfo = extractRequestedClaims(info.getUserInfoClaims());
    }


    private void setupVerifiedClaimsForUserInfo_Old(AuthorizationResponse info)
    {
        // "verified_claims" in "userinfo" in the "claims" request parameter.
        VerifiedClaimsConstraint verifiedClaimsConstraint =
                extractVerifiedClaims(info.getUserInfoClaims());

        if (verifiedClaimsConstraint == null)
        {
            return;
        }

        // Flag indicating whether the authorization request requests all
        // possible verified claims for userinfo.
        allVerifiedClaimsForUserInfoRequested =
                verifiedClaimsConstraint.isAllClaimsRequested();

        if (allVerifiedClaimsForUserInfoRequested == false)
        {
            // The authorization request explicitly lists verified claims.
            // Extract the list.
            verifiedClaimsForUserInfo =
                    extractRequestedClaims(verifiedClaimsConstraint);
        }
    }


    private static VerifiedClaimsConstraint extractVerifiedClaims(String claims)
    {
        if (claims == null)
        {
            return null;
        }

        // Parse the "verified_claims" that the JSON may contain.
        VerifiedClaimsConstraint constraint = VerifiedClaimsContainerConstraint
                .fromJson(claims).getVerifiedClaims();

        // If "verified_claims" is not included or its value is null.
        if (!constraint.exists() || constraint.isNull())
        {
            return null;
        }

        return constraint;
    }


    private static Pair[] extractRequestedClaims(VerifiedClaimsConstraint verifiedClaimsConstraint)
    {
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
            // Add a pair of claim name and its purpose.
            addVerifiedClaim(list, entry);
        }

        if (list.size() == 0)
        {
            return null;
        }

        return list.toArray(new Pair[list.size()]);
    }


    private static void addVerifiedClaim(List<Pair> list, Map.Entry<String, VerifiedClaimConstraint> entry)
    {
        String claimName = entry.getKey();
        String purpose   = entry.getValue().getPurpose();

        if (purpose == null)
        {
            purpose = "";
        }

        list.add(new Pair(claimName, purpose));
    }


    private boolean computeIdentityAssuranceRequired()
    {
        return purpose != null ||
               allVerifiedClaimsForIdTokenRequested ||
               verifiedClaimsForIdToken != null ||
               allVerifiedClaimsForUserInfoRequested ||
               verifiedClaimsForUserInfo != null
               ;
    }


    @SuppressWarnings("unchecked")
    private static Pair[] extractRequestedClaims(String claimsString)
    {
        if (claimsString == null)
        {
            return null;
        }

        // Interpret the string as JSON.
        Map<String, Object> claims =
                (Map<String, Object>)new Gson().fromJson(claimsString, Map.class);

        // The value of "verified_claims".
        Object verifiedClaims = claims.get("verified_claims");

        // Case 1: The value of "verified_claims" is a JSON array.
        if (verifiedClaims instanceof List)
        {
            return extractRequestedClaimsFromList((List<?>)verifiedClaims);
        }
        // Case 2: The value of "verified_claims" is a JSON object.
        else if (verifiedClaims instanceof Map)
        {
            return extractRequestedClaimsFromMap((Map<String, Object>)verifiedClaims);
        }
        else
        {
            return null;
        }
    }


    @SuppressWarnings("unchecked")
    private static Pair[] extractRequestedClaimsFromList(List<?> list)
    {
        List<Pair> pairList = new ArrayList<>();

        // For each element in the "verified_claims" array.
        for (Object element : list)
        {
            // If the element is not a JSON object.
            // (This case is a specification violation.)
            if (!(element instanceof Map))
            {
                // This element is ignored.
                continue;
            }

            // Extract pairs of claim name and "purpose" from "claims"
            // in the JSON object.
            Pair[] pairs = extractRequestedClaimsFromMap((Map<String, Object>)element);

            if (pairs == null)
            {
                continue;
            }

            pairList.addAll(Arrays.asList(pairs));
        }

        if (pairList.size() == 0)
        {
            return null;
        }

        // Convert the List instance to an array.
        return pairList.stream().toArray(Pair[]::new);
    }


    @SuppressWarnings("unchecked")
    private static Pair[] extractRequestedClaimsFromMap(Map<String, Object> map)
    {
        // The value of "claims".
        Object claims = map.get("claims");

        // If "claims" does not exist or its value is not a JSON object.
        if (!(claims instanceof Map))
        {
            // In either case, it's a specification violation.
            return null;
        }

        // "claims": {
        //    "{claimName1}": null,
        //    "{claimName2}": {
        //      "purpose": "...",
        //      ...
        //    },
        //    ....
        // }

        // Convert properties in "claims" into Pair's.
        Pair[] pairs = ((Map<String, Object>)claims).entrySet().stream()
                .map(entry -> extractClaimNamePurposePair(entry)).toArray(Pair[]::new);

        return (pairs.length != 0) ? pairs : null;
    }


    private static Pair extractClaimNamePurposePair(Map.Entry<String, Object> entry)
    {
        // "{claimName}": {
        //   "purpose": "...",
        //   ...
        // }

        String claimName = entry.getKey();
        String purpose   = extractPurpose(entry.getValue());

        return new Pair(claimName, purpose);
    }


    @SuppressWarnings("unchecked")
    private static String extractPurpose(Object value)
    {
        if (!(value instanceof Map))
        {
            return null;
        }

        // {
        //   "purpose": "...",
        //   ...
        // }

        Object purpose = ((Map<String, Object>)value).get("purpose");

        if (!(purpose instanceof String))
        {
            return null;
        }

        return (String)purpose;
    }
}
