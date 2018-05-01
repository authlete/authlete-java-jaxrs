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
package com.authlete.jaxrs;


import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;

import org.apache.commons.codec.binary.Base64;


/**
 * A base class for endpoints.
 *
 * @since 1.2
 *
 * @author Takahiko Kawasaki
 */
public class BaseEndpoint
{
    /** 
     * Headers to check for certificate path with proxy-forwarded certificate 
     * information; the first entry is the client's certificate itself 
     */
    private String[] clientCertificatePathHeaders = {
            "X-Ssl-Cert", // the client's certificate 
            "X-Ssl-Cert-Chain-1", "X-Ssl-Cert-Chain-2", "X-Ssl-Cert-Chain-3", "X-Ssl-Cert-Chain-4" // the intermediate certificate path, not including the client's certificate or root
    };
    
    /*
     * Used for handling PEM format certificates.
     */
    private Base64 base64 = new Base64(Base64.PEM_CHUNK_SIZE, "\n".getBytes());
    
    /**
     * Called when the internal request handler raises an exception.
     * The default implementation of this method calls {@code
     * printStackTrace()} of the given exception instance and does
     * nothing else. Override this method as necessary.
     *
     * @param exception
     *         An exception thrown by the internal request handler.
     */
    protected void onError(WebApplicationException exception)
    {
        exception.printStackTrace();
    }

    protected String[] extractClientCertificateChain(HttpServletRequest request)
    {
        // try to get the certificates from the servlet context directly
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        
        if (certs == null || certs.length == 0)
        {
            // we didn't find any certificates in the servlet request, try extracting them from the headers instead
            List<String> headerCerts = new ArrayList<>();
            
            for (String headerName : clientCertificatePathHeaders)
            {
                String header = request.getHeader(headerName);
                if (header != null)
                {
                    headerCerts.add(header);
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
        else 
        {
            String[] pemEncoded = new String[certs.length];
            
            try
            {
                for (int i = 0; i < certs.length; i++)
                {
                    // encode each certificate in PEM format
                    StringBuilder sb = new StringBuilder();
                    sb.append("-----BEGIN CERTIFICATE-----\n");
                    sb.append(base64.encode(certs[i].getEncoded()));
                    sb.append("\n-----END CERTIFICATE-----\n");

                    pemEncoded[i] = sb.toString();
                    
                }
            } catch (CertificateEncodingException e)
            {
                // TODO What should be done with this error?
                e.printStackTrace();
                return null;
            }
            
            return pemEncoded;
            
        }
        
    }
    
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
    
}
