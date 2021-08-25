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
package com.authlete.jaxrs;


import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.OuterList;
import org.greenbytes.http.sfv.Parser;


/**
 * A client certificate extractor for the {@code Client-Cert} and
 * {@code Client-Cert-Chain} headers.
 *
 * @since 2.34
 */
public class HeaderClientCertificateClientCertExtractor extends HeaderClientCertificateExtractor
{
    private List<String> clientCertificateChainHeaders = Arrays.asList(
            "Client-Cert",
            "Client-Cert-Chain");


    @Override
    public String[] extractClientCertificateChain(HttpServletRequest request)
    {
        List<ByteSequenceItem> listCert = new ArrayList<>();
        ByteSequenceItem[] byteSequenceCerts = new ByteSequenceItem[] {};

        for (String headerName : getClientCertificateChainHeaders())
        {
            String header = request.getHeader(headerName);
            OuterList parseCerts = Parser.parseList(header);
            byteSequenceCerts = parseCerts.get()
                    .toArray(new ByteSequenceItem[] {});

            for (ByteSequenceItem item : byteSequenceCerts)
            {
                listCert.add(item);
            }
        }

        if (listCert.size() < 1)
        {
            return null;
        }

        return decodeByteBufferCerts(listCert);
    }


    private String[] decodeByteBufferCerts(List<ByteSequenceItem> sequenceItems)
    {
        ArrayList<String> certs = new ArrayList<>();

        for (ByteSequenceItem item : sequenceItems)
        {
            certs.add(StandardCharsets.UTF_8.decode(item.get()).toString());
        }

        return certs.toArray(new String[] {});
    }


    @Override
    public List<String> getClientCertificateChainHeaders()
    {
        return clientCertificateChainHeaders;
    }


    @Override
    public HeaderClientCertificateExtractor setClientCertificateChainHeaders(
            List<String> clientCertificateChainHeaders)
    {
        throw new UnsupportedOperationException();
    }
}
