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
package com.authlete.jaxrs.spi;


import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.types.User;
import com.authlete.common.types.UserIdentificationHintType;


/**
 * Service Provider Interface to work with {@link com.authlete.jaxrs.BackchannelAuthenticationRequestHandler
 * BackchannelAuthenticationRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.BackchannelAuthenticationRequestHandler
 * BackchannelAuthenticationRequestHandler} class.
 * </p>
 *
 * @since 2.13
 *
 * @author Hideki Ikeda
 */
public interface BackchannelAuthenticationRequestHandlerSpi
{
    /**
     * Get a user by the hint.
     *
     * @param hintType
     *         The type of the hint contained in the backchannel authentication
     *         request.
     *
     * @param hint
     *         The hint contained in the backchannel authentication request.
     *         This value is equivalent to the value of the {@code "login_hint"}
     *         request parameter, the {@code "id_token_hint"} request parameter
     *         or the {@code "login_hint_token"} request parameter contained in
     *         the backchannel authentication request.
     *
     * @param sub
     *         The value of the {@code "sub"} claim of the ID token hint contained
     *         in the backchannel authentication request as the {@code "id_token_hint"}
     *         request parameter. This value is {@code null} if the backchannel
     *         authentication request does not contain the {@code "id_token_hint"}
     *         request parameter.
     *
     * @return
     *         A user identified by the hint. {@code null} is returned if a user
     *         is not found using the hint.
     */
    User getUserByHint(UserIdentificationHintType hintType, String hint, String sub);


    /**
     * Check whether the login hint token expired or not.
     *
     * <p>
     * This method is called only when the "login_hint_token" request parameter
     * is contained in the backchannel authentication request.
     * </p>
     *
     * @param loginHintToken
     *         The value of the "login_hint_token" request parameter contained in
     *         the backchannel authentication request..
     *
     * @return
     *         {@code true} if the login hint token has already expired. Otherwise,
     *         {@code false}.
     */
    boolean isLoginHintTokenExpired(String loginHintToken);


    /**
     * Check whether a user code should be checked or not.
     *
     * @param user
     *         A user from whom the client asks for authorization.
     *
     * @param info
     *         The information about the backchannel authentication request.
     *
     * @return
     *         {@code true} if a user code should be checked. Otherwise, {@code false}.
     */
    boolean shouldCheckUserCode(User user, BackchannelAuthenticationResponse info);


    /**
     * Check whether a user code is valid or not.
     *
     * <p>
     * This method is called only when {@link #shouldCheckUserCode(User, BackchannelAuthenticationResponse)}
     * returns {@code true}.
     * </p>
     *
     * @param user
     *         A user from whom the client asks for authorization.
     *
     * @param userCode
     *         A user code contained in the backchannel authentication request.
     *
     * @return
     *         {@code true} if a user code is valid. Otherwise, {@code false}.
     */
    boolean isValidUserCode(User user, String userCode);


    /**
     * Start a background process where the authorization server starts communicating
     * with an authentication device for end-user authentication and authorization.
     *
     * <p>
     * Typically this method will invoke a new thread in which the communication
     * between the authorization server and the authentication device will occur.
     * </p>
     *
     * @param user
     *         A user who is to be authenticated and asked to authorize the
     *         client application.
     *
     * @param info
     *         The information about the backchannel authentication request.
     */
    void startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse info);
}
