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


import java.util.Arrays;
import java.util.List;

public class HeaderClientCertificateXSslExtractor extends HeaderClientCertificateExtractor
{

  /**
   * Headers to check for certificate path with proxy-forwarded certificate
   * information; the first entry is the client's certificate itself
   */
  private List<String> clientCertificateChainHeaders = Arrays.asList(
      "X-Ssl-Cert", // the client's certificate
      "X-Ssl-Cert-Chain-1",
      "X-Ssl-Cert-Chain-2",
      "X-Ssl-Cert-Chain-3",
      "X-Ssl-Cert-Chain-4"
      // the intermediate certificate path, not including the client's
      // certificate or root
  );


  public List<String> getClientCertificateChainHeaders()
  {
    return clientCertificateChainHeaders;
  }

  @Override
  public HeaderClientCertificateExtractor setClientCertificateChainHeaders(
      List<String> clientCertificateChainHeaders) {
    throw new UnsupportedOperationException();
  }

}