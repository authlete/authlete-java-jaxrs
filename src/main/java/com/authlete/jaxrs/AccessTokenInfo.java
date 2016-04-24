/*
 * Copyright (C) 2016 Authlete, Inc.
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
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.Property;


/**
 * Information about an access token.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class AccessTokenInfo implements Serializable
{
    private static final long serialVersionUID = 2L;


    private String accessToken;
    private long clientId;
    private String subject;
    private String[] scopes;
    private long expiresAt;
    private Property[] properties;


    /**
     * The default constructor.
     */
    public AccessTokenInfo()
    {
    }


    /**
     * A constructor with an access token and a response from Authlete's
     * /api/auth/introspection API.
     *
     * @param accessToken
     *         An access token.
     *
     * @param info
     *         A response from Authlete's /api/auth/introspection API.
     *
     * @since 1.3
     */
    public AccessTokenInfo(String accessToken, IntrospectionResponse info)
    {
        this.accessToken = accessToken;
        this.clientId    = info.getClientId();
        this.subject     = info.getSubject();
        this.scopes      = info.getScopes();
        this.expiresAt   = info.getExpiresAt();
        this.properties  = info.getProperties();
    }


    /**
     * Get the value of the access token.
     *
     * @return
     *         The value of the access token.
     */
    public String getAccessToken()
    {
        return accessToken;
    }


    /**
     * Set the value of the access token.
     *
     * @param accessToken
     *         The value of the access token.
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setAccessToken(String accessToken)
    {
        this.accessToken = accessToken;

        return this;
    }


    /**
     * Get the ID of the client application which is associated
     * with the access token.
     *
     * @return
     *         The client ID.
     */
    public long getClientId()
    {
        return clientId;
    }


    /**
     * Set the ID of the client application which is associated
     * with the access token.
     *
     * @param clientId
     *         The client ID.
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setClientId(long clientId)
    {
        this.clientId = clientId;

        return this;
    }


    /**
     * Get the subject (= unique identifier) of the user who is
     * associated with the access token. This method returns
     * {@code null} if the access token was issued by <a href=
     * "http://tools.ietf.org/html/rfc6749#section-4.4">Client
     * Credentials Flow</a>.
     *
     * @return
     *         The subject (= unique identifier) of the user.
     */
    public String getSubject()
    {
        return subject;
    }


    /**
     * Set the subject (= unique identifier) of the user who is
     * associated with the access token.
     *
     * @param subject
     *         The subject (= unique identifier) of the user.
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setSubject(String subject)
    {
        this.subject = subject;

        return this;
    }


    /**
     * Get the scopes associated with the access token. This method
     * returns {@code null} if no scope was requested when an access
     * token was issued.
     *
     * @return
     *         The scopes.
     */
    public String[] getScopes()
    {
        return scopes;
    }


    /**
     * Set the scopes associated with the access token.
     *
     * @param scopes
     *         The scopes.
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setScopes(String[] scopes)
    {
        this.scopes = scopes;

        return this;
    }


    /**
     * Get the time at which the access token will expire.
     *
     * @return
     *         The time at which the access token will expire.
     *         Milliseconds since the Unix epoch (1970-01-01).
     */
    public long getExpiresAt()
    {
        return expiresAt;
    }


    /**
     * Set the time at which the access token will expire.
     *
     * @param expiresAt
     *         The time at which the access token will expire.
     *         Milliseconds since the Unix epoch (1970-01-01).
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setExpiresAt(long expiresAt)
    {
        this.expiresAt = expiresAt;

        return this;
    }


    /**
     * Get the extra properties associated with this access token.
     *
     * @return
     *         Extra properties. When no extra properties are associated
     *         with this access token, {@code null} is returned.
     *
     * @since 1.3
     */
    public Property[] getProperties()
    {
        return properties;
    }


    /**
     * Set the extra properties associated with the access token.
     *
     * @param properties
     *         Extra properties.
     *
     * @return
     *         {@code this} object.
     *
     * @since 1.3
     */
    public AccessTokenInfo setProperties(Property[] properties)
    {
        this.properties = properties;

        return this;
    }
}
