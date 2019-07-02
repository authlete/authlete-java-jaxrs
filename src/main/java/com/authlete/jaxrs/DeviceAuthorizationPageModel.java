/*
 * Copyright (C) 2019 Authlete, Inc.
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
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.Scope;


/**
 * Model class to hold data which are referred to in an authorization page in device
 * flow.
 *
 * <p>
 * Feel free to extend this class as necessary.
 * </p>
 *
 * @author Hideki Ikeda
 *
 * @since 2.18
 */
public class DeviceAuthorizationPageModel implements Serializable
{
    private static final long serialVersionUID = 1L;


    /**
     * The name of the client application.
     */
    private String clientName;


    /**
     * Scopes requested by the authorization request.
     */
    private Scope[] scopes;


    /**
     * The default constructor with default values.
     */
    public DeviceAuthorizationPageModel()
    {
    }


    /**
     * Create an {@link DeviceAuthorizationPageModel} instance using information
     * contained in an {@link DeviceVerificationResponse} object, which represents
     * a response from Authlete's {@code /api/device/verification} API.
     *
     * @param info
     *         An {@link DeviceVerificationResponse} object, which represents a
     *         response from Authlete's {@code /api/device/verification} API.
     */
    public DeviceAuthorizationPageModel(DeviceVerificationResponse info)
    {
        clientName = info.getClientName();
        scopes     = info.getScopes();
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
    public DeviceAuthorizationPageModel setClientName(String clientName)
    {
        this.clientName = clientName;

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
    public DeviceAuthorizationPageModel setScopes(Scope[] scopes)
    {
        this.scopes = scopes;

        return this;
    }
}
