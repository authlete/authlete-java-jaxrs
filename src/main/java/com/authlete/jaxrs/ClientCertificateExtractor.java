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


import javax.servlet.http.HttpServletRequest;


/**
 * Extracts a client's MTLS certificate from an incoming HTTP Request.
 *
 * @author jricher
 *
 * @since 2.8
 */
public interface ClientCertificateExtractor
{
    /**
     * Search the given request for a client's certificate and return it as a string
     * of certificates in PEM format.
     *
     * @param request
     *          The incoming HTTP request to search.
     *
     * @return
     *          The client's MTLS certificate chain. All certificates are in PEM format,
     *          the first certificate is the client's own certificate.
     */
    String[] extractClientCertificateChain(HttpServletRequest request);
}
