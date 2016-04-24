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
package com.authlete.jaxrs.spi;


import com.authlete.common.dto.Property;


/**
 * Empty implementation of {@link TokenRequestHandlerSpi} interface.
 *
 * <p>
 * If you don't support <a href="https://tools.ietf.org/html/rfc6749#section-4.3"
 * >Resource Owner Password Credentials Grant</a>, you don't have to
 * override {@link #authenticateUser(String, String)} method.
 * </p>
 *
 * @author Takahiko Kawasaki
 */
public class TokenRequestHandlerSpiAdapter implements TokenRequestHandlerSpi
{
    @Override
    public String authenticateUser(String username, String password)
    {
        return null;
    }


    @Override
    public Property[] getProperties()
    {
        return null;
    }
}
