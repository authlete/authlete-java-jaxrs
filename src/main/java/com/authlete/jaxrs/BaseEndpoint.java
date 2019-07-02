/*
 * Copyright (C) 2016-2018 Authlete, Inc.
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
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.WebApplicationException;


/**
 * A base class for endpoints.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class BaseEndpoint
{
    private List<ClientCertificateExtractor> clientCertificateExtractors = Arrays.asList(
            new HttpsRequestClientCertificateExtractor(),
            new HeaderClientCertificateExtractor()
            );


    /**
     * Called when the internal request handler raises an exception.
     * The default implementation of this method does nothing.
     * Override this method as necessary.
     *
     * @param exception
     *         An exception thrown by the internal request handler.
     */
    protected void onError(WebApplicationException exception)
    {
    }


    /**
     * Utility method for extracting a single client certificate from the default
     * certificate extractors. First checks the request itself for an attached
     * certificate using {@link javax.servlet.request.X509Certificate}, then
     * checks the incoming request headers for reverse-proxied certificates
     * using default headers.
     *
     * @see ClientCertificateExtractor
     *
     * @param request
     *         The incoming HTTP request to search for the client's certificate.
     *
     * @return
     *         The client's mutual TLS certificate.
     *
     * @since 2.8
     */
    protected String[] extractClientCertificateChain(HttpServletRequest request)
    {
        for (ClientCertificateExtractor extractor : clientCertificateExtractors)
        {
            String[] chain = extractor.extractClientCertificateChain(request);
            if (chain != null && chain.length > 0)
            {
                return chain;
            }
        }

        return null;
    }


    /**
     * Utility method for extracting a single client certificate from the default
     * certificate extractors. Calls extractClientCertificateChain and returns the
     * first entry in the array, if any, null otherwise.
     *
     * @param request
     *         The incoming HTTP request to search for the client's certificate.
     *
     * @return
     *         The client's mutual TLS certificate.
     *
     * @since 2.8
     */
    protected String extractClientCertificate(HttpServletRequest request)
    {
        String[] certs = extractClientCertificateChain(request);

        if (certs != null && certs.length > 0)
        {
            return certs[0];
        }
        else
        {
            return null;
        }
    }


    /**
     * Get the value of an attribute from the given session and
     * remove the attribute from the session after the retrieval.
     *
     * @param session
     *         The session from which the value of the attribute is extracted.
     *
     * @param key
     *         The key associated with the target attribute.
     *
     * @return
     *         The value of the attribute associated with the given key.
     *
     * @since 2.18
     */
    protected Object takeAttribute(HttpSession session, String key)
    {
        // Retrieve the value from the session.
        Object value = session.getAttribute(key);

        // Remove the attribute from the session.
        session.removeAttribute(key);

        // Return the value of the attribute.
        return value;
    }
}
