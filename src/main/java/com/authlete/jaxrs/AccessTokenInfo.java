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


/**
 * Information about an access token.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class AccessTokenInfo implements Serializable
{
    private static final long serialVersionUID = 1L;


    private String accessToken;
    private long clientId;
    private String subject;
    private String[] scopes;
    private long expiresAt;


    public AccessTokenInfo()
    {
    }


    AccessTokenInfo(String accessToken, IntrospectionResponse info)
    {
        this.accessToken = accessToken;
        this.clientId    = info.getClientId();
        this.subject     = info.getSubject();
        this.scopes      = info.getScopes();
        this.expiresAt   = info.getExpiresAt();
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
     * Get the time at which the access token will expire.
     *
     * @return
     *         The time at which the access token will expire.
     */
    public long getExpiresAt()
    {
        return expiresAt;
    }
}
