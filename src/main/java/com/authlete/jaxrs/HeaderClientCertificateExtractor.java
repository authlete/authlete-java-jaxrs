package com.authlete.jaxrs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * 
 * Extracts the client certificate from headers defined by the {@code 
 * clientCertificateChainHeaders} member list. The first element in the list is 
 * header for the client's own certificate. Each additional header in the list
 * will be checked and added to the resulting output.
 * 
 * @author jricher
 *
 * @since 2.8
 *
 */
public class HeaderClientCertificateExtractor implements ClientCertificateExtractor
{

    /** 
     * Headers to check for certificate path with proxy-forwarded certificate 
     * information; the first entry is the client's certificate itself 
     */
    private List<String> clientCertificateChainHeaders = Arrays.asList(
            "X-Ssl-Cert", // the client's certificate 
            "X-Ssl-Cert-Chain-1", "X-Ssl-Cert-Chain-2", "X-Ssl-Cert-Chain-3", "X-Ssl-Cert-Chain-4" // the intermediate certificate path, not including the client's certificate or root
    );
    
    /* (non-Javadoc)
     * @see com.authlete.jaxrs.ClientCertificateExtractor#extractClientCertificateChain(javax.servlet.http.HttpServletRequest)
     */
    @Override
    public String[] extractClientCertificateChain(HttpServletRequest request)
    {
        List<String> headerCerts = new ArrayList<>();
        
        // look through all the headers that we've been configured with and pull out their values
        for (String headerName : getClientCertificateChainHeaders())
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

    /**
     * Get the headers that will be checked for the client certificate chain. The first element in 
     * the list is header for the client's own certificate. Each additional header in the list
     * will be checked and added to the resulting output.
     */
    public List<String> getClientCertificateChainHeaders()
    {
        return clientCertificateChainHeaders;
    }

    /**
     * Set the headers that will be checked for the client certificate chain. The first element in 
     * the list is header for the client's own certificate. Each additional header in the list
     * will be checked and added to the resulting output.
     */
    public HeaderClientCertificateExtractor setClientCertificateChainHeaders(List<String> clientCertificateChainHeaders)
    {
        this.clientCertificateChainHeaders = clientCertificateChainHeaders;
        
        return this;
    }

}
