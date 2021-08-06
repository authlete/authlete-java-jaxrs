/*
 * Copyright (C) 2018-2020 Authlete, Inc.
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


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;


/**
 * Extracts the client certificate from headers defined by the {@code
 * clientCertificateChainHeaders} member list. The first element in the list is
 * header for the client's own certificate. Each additional header in the list
 * will be checked and added to the resulting output.
 *
 * <p>
 * Headers that are missing, empty, or contain only the string {@code "(null)"}
 * are not returned in the list.
 * </p>
 *
 * <p>
 * Different proxy servers use different configuration methods. For the Apache
 * server, one possible method using the default headers for this class is below:
 * </p>
 *
 * <pre>
 *   SSLEngine on
 *   SSLCertificateFile /etc/certs/tls.crt
 *   SSLCertificateKeyFile /etc/certs/tls.key
 *   SSLVerifyClient optional_no_ca
 *   SSLOptions +StdEnvVars +ExportCertData
 *   RequestHeader set X-Ssl-Cipher "%{SSL_CIPHER}e" env=SSL_CIPHER
 *   RequestHeader set X-Ssl-Cert "%{SSL_CLIENT_CERT}e" env=SSL_CLIENT_CERT
 *   RequestHeader set X-Ssl-Protocol "%{SSL_PROTOCOL}e" env=SSL_PROTOCOL
 *   RequestHeader set X-Ssl-Verify "%{SSL_CLIENT_VERIFY}e" env=SSL_CLIENT_VERIFY
 *   RequestHeader set X-Ssl-Cert-Chain-1 "%{SSL_CLIENT_CERT_CHAIN_1}e" env=SSL_CLIENT_CERT_CHAIN_1
 *   RequestHeader set X-Ssl-Cert-Chain-2 "%{SSL_CLIENT_CERT_CHAIN_2}e" env=SSL_CLIENT_CERT_CHAIN_2
 *   RequestHeader set X-Ssl-Cert-Chain-3 "%{SSL_CLIENT_CERT_CHAIN_3}e" env=SSL_CLIENT_CERT_CHAIN_3
 *   RequestHeader set X-Ssl-Cert-Chain-4 "%{SSL_CLIENT_CERT_CHAIN_4}e" env=SSL_CLIENT_CERT_CHAIN_4
 *   ProxyPreserveHost on
 *   ProxyPass "/" "http://localhost:8081/"
 *   ProxyPassReverse "/" "http://localhost:8081/"
 * </pre>
 *
 * <p>
 * On the other hand, Nginx's configuration file may have the following line.
 * </p>
 *
 * <pre>
 *   proxy_set_header X-Ssl-Cert $ssl_client_escaped_cert;
 * </pre>
 *
 * <p>
 * Note that {@code $ssl_client_cert} is deprecated and it will cause an error
 * when the value is sent to an upstream server which strictly conforms to the
 * requirement described in "Section 3.2.4. Field Parsing" in RFC 7230. The RFC
 * deprecates "line folding" which enables HTTP header values to span multiple
 * lines by preceding each extra line with at least one space or horizontal tab.
 * For example, Jetty reports "Bad Message 400 / reason: Header Folding" when
 * it encounters line folding.
 * </p>
 *
 * @author jricher
 *
 * @since 2.8
 */
public abstract class HeaderClientCertificateExtractor implements ClientCertificateExtractor
{

    /**
     * Headers to check for certificate path with proxy-forwarded certificate
     * information; the first entry is the client's certificate itself
     */
    private List<String> clientCertificateChainHeaders;

    @Override
    public String[] extractClientCertificateChain(HttpServletRequest request)
    {
        List<String> headerCerts = new ArrayList<>();

        // look through all the headers that we've been configured with and
        // pull out their values
        for (String headerName : getClientCertificateChainHeaders())
        {
            String header = request.getHeader(headerName);
            String cert   = normalizeCert(header);

            if (cert != null)
            {
                headerCerts.add(cert);
            }
        }

        if (headerCerts.isEmpty())
        {
            return null;
        }
        else
        {
            return headerCerts.toArray(new String[] {});
        }
    }


    private static String normalizeCert(String cert)
    {
        if (cert == null || cert.isEmpty())
        {
            return null;
        }

        // "(null)" is a value that misconfigured Apache servers will send
        // instead of a missing header.
        if (cert.equals("(null)"))
        {
            return null;
        }

        // Nginx's $ssl_client_escaped_cert holds a "urlencoded" client
        // certificate in the PEM format.
        if (cert.startsWith("-----BEGIN%20"))
        {
            cert = urlDecode(cert);
        }

        return cert;
    }


    private static String urlDecode(String input)
    {
        try
        {
            return URLDecoder.decode(input, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            // Failed to decode the input string.
            return input;
        }
    }


    /**
     * Get the headers that will be checked for the client certificate chain.
     * The first element in the list is header for the client's own certificate.
     * Each additional header in the list will be checked and added to the
     * resulting output.
     */
    public List<String> getClientCertificateChainHeaders()
    {
        return clientCertificateChainHeaders;
    }


    /**
     * Set the headers that will be checked for the client certificate chain.
     * The first element in the list is header for the client's own certificate.
     * Each additional header in the list will be checked and added to the
     * resulting output.
     */
    public HeaderClientCertificateExtractor setClientCertificateChainHeaders(
            List<String> clientCertificateChainHeaders)
    {
        this.clientCertificateChainHeaders = clientCertificateChainHeaders;

        return this;
    }
}
