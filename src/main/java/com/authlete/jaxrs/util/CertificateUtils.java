/*
 * Copyright (C) 2021 Authlete, Inc.
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
package com.authlete.jaxrs.util;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import com.authlete.jaxrs.ClientCertificateExtractor;
import com.authlete.jaxrs.HeaderClientCertificateClientCertExtractor;
import com.authlete.jaxrs.HeaderClientCertificateXSslExtractor;
import com.authlete.jaxrs.HttpsRequestClientCertificateExtractor;


/**
 * Utilities for certificates.
 *
 * @since 2.32
 */
public class CertificateUtils
{
    /**
     * A list of known implementations each of which extracts a client certificate
     * chain from {@link HttpServletRequest}.
     *
     * <p>
     * There are several ways for a web application to receive a client certificate.
     * </p>
     *
     * <p>
     * In a typical case, a web application sits behind a reverse proxy and the
     * client certificate used in the mutual TLS connection between the client
     * application and the reverse proxy is passed to the web application via a
     * special HTTP header such as {@code X-Ssl-Cert}. However, it depends on
     * how the reverse proxy is configured.
     * </p>
     *
     * <p>
     * Note that there is a specification draft that tries to standardize the
     * name of the HTTP header and the format of its value. The specification
     * is "<a href=
     * "https://datatracker.ietf.org/doc/draft-ietf-httpbis-client-cert-field/"
     * >Client-Cert HTTP Header Field: Conveying Client Certificate Information
     * from TLS Terminating Reverse Proxies to Origin Server Applications</a>".
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-httpbis-client-cert-field/"
     *      >Client-Cert HTTP Header Field: Conveying Client Certificate Information
     *      from TLS Terminating Reverse Proxies to Origin Server Applications</a>
     */
    private static final List<ClientCertificateExtractor> CLIENT_CERTIFICATE_EXTRACTORS
    = Collections.unmodifiableList(Arrays.asList(
            new HttpsRequestClientCertificateExtractor(),
            new HeaderClientCertificateXSslExtractor(),
            new HeaderClientCertificateClientCertExtractor()
    ));


    /**
     * Extract a client certificate chain from an HTTP request using known
     * implementations of {@link ClientCertificateExtractor}.
     *
     * @param request
     *         An HTTP request.
     *
     * @return
     *         A client certificate chain. If a non-null value is
     *         returned, the first element is a client certificate.
     */
    public static String[] extractChain(HttpServletRequest request)
    {
        return extractChain(CLIENT_CERTIFICATE_EXTRACTORS, request);
    }


    /**
     * Extract a client certificate chain from an HTTP request using the
     * given list of {@link ClientCertificateExtractor} implementations.
     *
     * @param extractors
     *         A list of {@link ClientCertificateExtractor} implementations.
     *
     * @param request
     *         An HTTP request.
     *
     * @return
     *         A client certificate chain. If a non-null value is
     *         returned, the first element is a client certificate.
     */
    public static String[] extractChain(
            List<ClientCertificateExtractor> extractors, HttpServletRequest request)
    {
        if (extractors == null || request == null)
        {
            return null;
        }

        for (ClientCertificateExtractor extractor : extractors)
        {
            if (extractor == null)
            {
                continue;
            }

            String[] chain = extractor.extractClientCertificateChain(request);

            if (chain != null && chain.length != 0)
            {
                return chain;
            }
        }

        return null;
    }


    /**
     * Extract a client certificate from an HTTP request using known
     * implementations of {@link ClientCertificateExtractor}.
     *
     * @param request
     *         An HTTP request.
     *
     * @return
     *         A client certificate.
     */
    public static String extract(HttpServletRequest request)
    {
        return extract(CLIENT_CERTIFICATE_EXTRACTORS, request);
    }


    /**
     * Extract a client certificate from an HTTP request using the given
     * list of {@link ClientCertificateExtractor} implementations.
     *
     * @param extractors
     *         A list of {@link ClientCertificateExtractor} implementations.
     *
     * @param request
     *         An HTTP request.
     *
     * @return
     *         A client certificate.
     */
    public static String extract(
            List<ClientCertificateExtractor> extractors, HttpServletRequest request)
    {
        String[] chain = extractChain(extractors, request);

        return (chain == null) ? null : chain[0];
    }
}
