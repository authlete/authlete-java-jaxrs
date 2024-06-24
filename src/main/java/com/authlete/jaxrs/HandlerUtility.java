/*
 * Copyright (C) 2024 Authlete, Inc.
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


import java.util.Arrays;
import com.authlete.common.web.BasicCredentials;


/**
 * Utility for handlers.
 *
 * @since 2.79
 */
class HandlerUtility
{
    private HandlerUtility()
    {
    }


    public static String[] extractClientCredentialFromAuthorization(String authorization)
    {
        // Interpret the content of the Authorization header as
        // client credential if possible.
        BasicCredentials credentials = BasicCredentials.parse(authorization);

        // The credentials of the client application extracted from
        // 'Authorization' header. These may be null.
        String clientId     = credentials == null ? null : credentials.getUserId();
        String clientSecret = credentials == null ? null : credentials.getPassword();

        return new String[] { clientId, clientSecret };
    }


    public static String extractClientCertificate(String[] clientCertificatePath)
    {
        if (clientCertificatePath == null || clientCertificatePath.length == 0)
        {
            // A client certificate is unavailable.
            return null;
        }

        // The first one in the certificate path is the client's certificate.
        return clientCertificatePath[0];
    }


    public static String[] extractSubsequenceFromClientCertificatePath(String[] clientCertificatePath)
    {
        if (clientCertificatePath == null || clientCertificatePath.length == 0)
        {
            // No adjustment.
            return clientCertificatePath;
        }

        // Extract the second and subsequent elements.
        // (= Remove the first element.)
        return Arrays.copyOfRange(clientCertificatePath, 1, clientCertificatePath.length);
    }
}
