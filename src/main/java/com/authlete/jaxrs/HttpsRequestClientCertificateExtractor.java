/**
 * 
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
 *
 */
public class HttpsRequestClientCertificateExtractor implements ClientCertificateExtractor
{

    /*
     * Used for handling PEM format certificates.
     */
    private Base64 base64 = new Base64(Base64.PEM_CHUNK_SIZE, "\n".getBytes());

    /* (non-Javadoc)
     * @see com.authlete.jaxrs.ClientCertificateExtractor#extractClientCertificateChain(javax.servlet.http.HttpServletRequest)
     */
    @Override
    public String[] extractClientCertificateChain(HttpServletRequest request)
    {
        // try to get the certificates from the servlet context directly
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        
        if (certs == null || certs.length == 0)
        {
            return null;
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

}
