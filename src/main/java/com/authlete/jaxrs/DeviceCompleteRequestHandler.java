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


import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.DeviceCompleteRequest;
import com.authlete.common.dto.DeviceCompleteRequest.Result;
import com.authlete.common.dto.DeviceCompleteResponse.Action;
import com.authlete.common.dto.Property;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.jaxrs.spi.DeviceCompleteRequestHandlerSpi;


/**
 * Handler for processing the result of end-user authentication and authorization
 * in OAuth 2.0 Device Authorization Grant (Device Flow).
 *
 * <p>
 * {@link #handle(String, String[]) handle()} method should be called after the
 * authorization server receives the result of end-user authentication and authorization,
 * or even in the case where the server gave up getting the result for some reasons.
 * The {@code handle()} method calls Authlete's {@code /api/device/complete}
 * API, receives a response from the API, and dispatches processing according to
 * the {@code action} parameter in the response.
 * </p>
 *
 * @author Hideki Ikeda
 *
 * @since 2.18
 */
public class DeviceCompleteRequestHandler extends BaseHandler
{
    /**
     * Implementation of {@link DeviceCompleteRequestHandlerSpi} interface.
     */
    private final DeviceCompleteRequestHandlerSpi mSpi;


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface
     * and an implementation of {@link DeviceCompleteRequestHandlerSpi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     *
     * @param spi
     *         Implementation of {@link DeviceCompleteRequestHandlerSpi} interface.
     */
    public DeviceCompleteRequestHandler(AuthleteApi api, DeviceCompleteRequestHandlerSpi spi)
    {
        super(api);

        mSpi = spi;
    }


    /**
     * Handle the result of end-user authentication and authorization in OAuth
     * 2.0 Device Authorization Grant (Device Flow).
     *
     * @param userCode
     *         The user code that the end-user inputed.
     *
     * @param claimNames
     *         Names of requested claims. Use the value of the {@code claimNames}
     *         parameter in a response from Authlete's {@code /api/device/verification}
     *         API.
     *
     * @return
     *         A response that should be returned to the end-user.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(String userCode, String[] claimNames) throws WebApplicationException
    {
        try
        {
            // Process the given parameters.
            return process(userCode, claimNames);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in DeviceCompleteRequestHandler", t);
        }
    }


    private Response process(String userCode, String[] claimNames)
    {
        // Call Authlete's /api/device/complete API.
        DeviceCompleteResponse response = complete(userCode, claimNames);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // Dispatch according to the action.
        switch (action)
        {
            case SUCCESS:
                // The API call has been processed successfully.
                return mSpi.onSuccess();

            case INVALID_REQUEST:
                // The API call was invalid.
                return mSpi.onInvalidRequest();

            case USER_CODE_EXPIRED:
                // The user code has expired.
                return mSpi.onUserCodeExpired();

            case USER_CODE_NOT_EXIST:
                // The user code does not exist.
                return mSpi.onUserCodeNotExist();

            case SERVER_ERROR:
                // An error occurred on Authlete side.
                return mSpi.onServerError();

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/device/complete", action);
        }
    }


    private DeviceCompleteResponse complete(String userCode, String[] claimNames)
    {
        // Get the result of end-user authentication and authorization.
        Result result = mSpi.getResult();

        if (result != Result.AUTHORIZED)
        {
            // Get the description of the error.
            String errorDescription = mSpi.getErrorDescription();

            // Get the URI of a document which describes the error in detail.
            URI errorUri = mSpi.getErrorUri();

            // The end-user has not successfully authorized the client.
            // Then, complete the process with failure.
            return fail(userCode, result, errorDescription, errorUri);
        }

        // OK. The end-user has successfully authorized the client.

        // Get the subject of the user.
        String subject = mSpi.getUserSubject();

        // Get the authentication time.
        long authTime = mSpi.getUserAuthenticatedAt();

        // Collect the user's claims.
        Map<String, Object> claims = collectClaims(claimNames);

        // Get the acr value that was actually used.
        String acr = mSpi.getAcr();

        // Scopes to associate with an access token.
        // If a non-null value is returned from mSpi.getScopes(), the scope set
        // replaces the scopes that have been specified in the original
        // device authorization request.
        String[] scopes = mSpi.getScopes();

        // Properties to associate with an access token.
        Property[] properties = mSpi.getProperties();

        // Complete the process with successful authorization.
        return authorize(userCode, subject, authTime, acr, claims, properties, scopes);
    }


    // TODO: Duplicate code.
    private Map<String, Object> collectClaims(String[] requestedClaimNames)
    {
        if (requestedClaimNames == null || requestedClaimNames.length == 0)
        {
            // No claim is requested by the client.
            return null;
        }

        // Claim values.
        Map<String, Object> claims = new HashMap<String, Object>();

        for (String name : requestedClaimNames)
        {
            if (name == null || name.length() == 0)
            {
                continue;
            }

            Object value = mSpi.getUserClaim(name);

            if (value == null)
            {
                continue;
            }

            claims.put(name, value);
        }

        if (claims.size() == 0)
        {
            return null;
        }

        return claims;
    }


    private DeviceCompleteResponse authorize(
            String userCode, String subject, long authTime, String acr, Map<String, Object> claims,
            Property[] properties, String[] scopes)
    {
        return callDeviceComlete(
                userCode, subject, Result.AUTHORIZED, authTime, acr, claims,
                properties, scopes, null, null);
    }


    private DeviceCompleteResponse fail(
            String userCode, Result result, String errorDescription, URI errorUri)
    {
        return callDeviceComlete(
                userCode, null, result, 0, null, null, null, null, errorDescription,
                errorUri);
    }


    private DeviceCompleteResponse callDeviceComlete(
            String userCode, String subject, DeviceCompleteRequest.Result result,
            long authTime, String acr, Map<String, Object> claims, Property[] properties,
            String[] scopes, String errorDescription, URI errorUri)
    {
        return getApiCaller().callDeviceComplete(
                userCode, subject, result, authTime, acr, claims, properties, scopes,
                errorDescription, errorUri);
    }
}
