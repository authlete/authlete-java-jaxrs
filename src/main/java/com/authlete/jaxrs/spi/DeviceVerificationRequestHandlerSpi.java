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
package com.authlete.jaxrs.spi;


import javax.ws.rs.core.Response;
import com.authlete.common.dto.DeviceVerificationResponse;


/**
 * Service Provider Interface to work with {@link
 * com.authlete.jaxrs.DeviceVerificationRequestHandler DeviceVerificationRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.DeviceVerificationRequestHandler DeviceVerificationRequestHandler}
 * class.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public interface DeviceVerificationRequestHandlerSpi
{
    /**
     * Get the value of the user code that the end-user input.
     *
     * @return
     *         The value of the user code that the end-user input.
     */
    String getUserCode();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/verification} API
     * is {@link com.authlete.common.dto.DeviceVerificationResponse.Action#VALID
     * VALID}, which means the user code exists, has not expired, and belongs to
     * the service. Typically, the authorization server implementation should
     * interact with the end-user to ask whether she approves or rejects the
     * authorization request from the device.
     *
     * @param info
     *         A Response from Authlete's {@code /api/device/verification} API.
     *
     * @return
     *         A response to the end-user.
     */
    Response onValid(DeviceVerificationResponse info);


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/verification} API
     * is {@link com.authlete.common.dto.DeviceVerificationResponse.Action#EXPIRED
     * EXPIRED}, which means the user code has expired. Typically, the authorization
     * server implementation should tell the end-user that the user code has expired
     * and urge her to re-initiate a device flow.
     *
     * @return
     *         A response to the end-user.
     */
    Response onExpired();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/verification} API
     * is {@link com.authlete.common.dto.DeviceVerificationResponse.Action#NOT_EXIST
     * NOT_EXIST}, which means the user code does not exist. Typically, the authorization
     * server implementation should tell the end-user that the user code is invalid
     * and urge her to retry to input a valid user code.
     *
     * @return
     *         A response to the end-user.
     */
    Response onNotExist();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/verification} API
     * is {@link com.authlete.common.dto.DeviceVerificationResponse.Action#SERVER_ERROR
     * SERVER_ERROR}, which means an error occurred on Authlete side. Typically,
     * the authorization server implementation should tell the end-user that something
     * wrong happened and urge her to re-initiate a device flow.
     *
     * @return
     *         A response to the end-user.
     */
    Response onServerError();
}
