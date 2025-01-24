/*
 * Copyright (C) 2024 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.authlete.jaxrs.util;


import static org.junit.jupiter.api.Assertions.assertEquals;

import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;


public class RequestUrlResolverTest
{
    @Test
    public void test_by_configuration()
    {
        // Request
        HttpServletRequest request = createMockRequest();

        // Resolver
        RequestUrlResolver resolver =
                new RequestUrlResolver().setScheme("https").setHost("example.com");

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_url_field_default()
    {
        // Request URL
        String originalUrl = "https://example.com/path2?key2=value2";

        // Request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Forwarded-URL")).thenReturn(originalUrl);

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals(originalUrl, url);
    }


    @Test
    public void test_by_url_field_custom()
    {
        // Custom HTTP field for the request URL.
        String urlFieldName = "My-Forwarded-URL";

        // Request URL
        String originalUrl = "https://example.com/path2?key2=value2";

        // Request
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader(urlFieldName)).thenReturn(originalUrl);

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver()
                .setUrlFieldName(urlFieldName);

        // Resolve
        String url = resolver.resolve(request);

        assertEquals(originalUrl, url);
    }


    @Test
    public void test_by_forwarded_field()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("Forwarded")).thenReturn("proto=https;host=example.com");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_x_proto()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("X-Forwarded-Proto")).thenReturn("https");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_x_protocol()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("X-Forwarded-Protocol")).thenReturn("https");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_x_url_scheme()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("X-Url-Scheme")).thenReturn("https");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_x_forwarded_ssl_off()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("X-Forwarded-Ssl")).thenReturn("off");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("http://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_x_forwarded_ssl_on()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("X-Forwarded-Ssl")).thenReturn("on");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_front_end_https_off()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("Front-End-Https")).thenReturn("off");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("http://example.com/path?key=value", url);
    }


    @Test
    public void test_by_de_facto_fields_front_end_https_on()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getHeader("X-Forwarded-Host")).thenReturn("example.com");
        Mockito.when(request.getHeader("Front-End-Https")).thenReturn("on");

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("https://example.com/path?key=value", url);
    }


    @Test
    public void test_by_request()
    {
        // Request
        HttpServletRequest request = createMockRequest();
        Mockito.when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/path"));

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("http://localhost:8080/path?key=value", url);
    }


    /**
     * Creates a mock {@link HttpServletRequest} that by default has the URI set to `/path`
     * and the query string set to `key=value`
     *
     * @return the constructed mock {@link HttpServletRequest}
     */
    private HttpServletRequest createMockRequest()
    {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getRequestURI()).thenReturn("/path");
        Mockito.when(request.getQueryString()).thenReturn("key=value");

        return request;
    }
}
