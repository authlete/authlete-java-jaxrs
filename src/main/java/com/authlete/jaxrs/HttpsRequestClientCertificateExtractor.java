/*
 * Copyright (C) 2018 Authlete, Inc.
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


import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.codec.binary.Base64;


/**
 * Extracts the client certificate from the incoming HTTPS request using the
 * {@link javax.servlet.request.X509Certificate} attribute.
 *
 * @author jricher
 *
 * @since 2.8
 */
public class HttpsRequestClientCertificateExtractor implements ClientCertificateExtractor
{
    /*
     * Used for handling PEM format certificates.
     */
    private Base64 base64 = new Base64(Base64.PEM_CHUNK_SIZE, "\n".getBytes());


    @Override
    public String[] extractClientCertificateChain(HttpServletRequest request)
    {
        // try to get the certificates from the servlet context directly
        X509Certificate[] certs = (X509Certificate[])
                request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs == null || certs.length == 0)
        {
            return null;
        }

        String[] pemEncoded = new String[certs.length];

        try
        {
            // encode each certificate in PEM format
            for (int i = 0; i < certs.length; i++)
            {
                pemEncoded[i] = toPEM(certs[i]);
            }
        }
        catch (CertificateEncodingException e)
        {
            // Failed to get the PEM format of the certificate,
            // but this is unlikely to happen.
            return null;
        }

        return pemEncoded;
    }


    private String toPEM(X509Certificate certificate) throws CertificateEncodingException
    {
        StringBuilder sb = new StringBuilder();

        sb.append("-----BEGIN CERTIFICATE-----\n");
        sb.append(base64.encode(certificate.getEncoded()));
        sb.append("\n-----END CERTIFICATE-----\n");

        return sb.toString();
    }
}
