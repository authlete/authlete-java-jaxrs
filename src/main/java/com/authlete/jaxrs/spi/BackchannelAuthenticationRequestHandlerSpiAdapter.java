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


import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.types.User;
import com.authlete.common.types.UserIdentificationHintType;


/**
 * Empty implementation of {@link BackchannelAuthenticationRequestHandlerSpi} interface.
 *
 * @since 2.13
 *
 * @author Hideki Ikeda
 */
public class BackchannelAuthenticationRequestHandlerSpiAdapter implements BackchannelAuthenticationRequestHandlerSpi
{
    @Override
    public User getUserByHint(UserIdentificationHintType hintType, String hint, String sub)
    {
        return null;
    }


    @Override
    public boolean isLoginHintTokenExpired(String loginHintToken)
    {
        return false;
    }


    @Override
    public boolean shouldCheckUserCode(User user, BackchannelAuthenticationResponse info)
    {
        return false;
    }


    @Override
    public boolean isValidUserCode(User user, String userCode)
    {
        return false;
    }


    @Override
    public void startCommunicationWithAuthenticationDevice(User user, BackchannelAuthenticationResponse baRes,
            BackchannelAuthenticationIssueResponse baiRes)
    {
    }


    @Override
    public boolean isValidBindingMessage(String bindingMessage)
    {
        return false;
    }
}
