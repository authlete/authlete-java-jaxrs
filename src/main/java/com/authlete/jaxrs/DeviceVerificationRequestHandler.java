/*
 * Copyright (C) 2019-2022 Authlete, Inc.
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
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.DeviceVerificationResponse.Action;
import com.authlete.jaxrs.spi.DeviceVerificationRequestHandlerSpi;


/**
 * Handler for getting information associated with a user code that the end-user
 * input at the verification endpoint in OAuth 2.0 Device Authorization Grant
 * (Device Flow).
 *
 * <p>
 * {@link #handle()} method should be called after the
 * authorization server receives a user code that the end-user input at the verification
 * endpoint. The {@code handle()} method calls Authlete's {@code /api/device/verification}
 * API, receives a response from the API, and dispatches processing according to
 * the {@code action} parameter in the response.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public class DeviceVerificationRequestHandler extends BaseHandler
{
    /**
     * Implementation of {@link DeviceVerificationRequestHandlerSpi} interface.
     */
    private final DeviceVerificationRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link DeviceVerificationRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link DeviceVerificationRequestHandlerSpi} interface.
     */
    public DeviceVerificationRequestHandler(AuthleteApi api, DeviceVerificationRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle information associated with a user code that the end-user
     * input at the verification endpoint in OAuth 2.0 Device Authorization Grant
     * (Device Flow).
     *
     * @return
     *         A response that should be returned to the end-user.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle() throws WebApplicationException
    {
        try
        {
            // Process the given parameters.
            return process();
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in DeviceVerificationRequestHandler", t);
        }
    }


    private Response process()
    {
        // Call Authlete's /api/device/verification API.
        DeviceVerificationResponse response = getApiCaller().callDeviceVerification(mSpi.getUserCode());

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // Dispatch according to the action.
        switch (action)
        {
            case VALID:
                // The user code is valid.
                // Ask the user to authorize the client.
                return mSpi.onValid(response);

            case EXPIRED:
                // The user code has expired.
                // Urge the user to re-initiate device flow.
                return mSpi.onExpired();

            case NOT_EXIST:
                // The user code does not exist.
                // Urge the user to re-input a valid user code.
                return mSpi.onNotExist();

            case SERVER_ERROR:
                // An error occurred on Authlete.
                // Urge the user to re-initiate device flow.
                return mSpi.onServerError();

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/device/verification", action);
        }
    }
}
