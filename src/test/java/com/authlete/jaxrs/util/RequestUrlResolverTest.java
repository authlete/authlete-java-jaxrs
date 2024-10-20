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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import org.junit.jupiter.api.Test;


public class RequestUrlResolverTest
{
    @Test
    public void test_by_configuration()
    {
        // Request
        HttpServletRequest request = new TestRequest();

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-URL", originalUrl);

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
        HttpServletRequest request = new TestRequest()
                .addHeader(urlFieldName, originalUrl);

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
        HttpServletRequest request = new TestRequest()
                .addHeader("Forwarded", "proto=https;host=example.com");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("X-Forwarded-Proto", "https");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("X-Forwarded-Protocol", "https");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("X-Url-Scheme", "https");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("X-Forwarded-Ssl", "off");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("X-Forwarded-Ssl", "on");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("Front-End-Https", "off");

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
        HttpServletRequest request = new TestRequest()
                .addHeader("X-Forwarded-Host", "example.com")
                .addHeader("Front-End-Https", "on");

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
        HttpServletRequest request = new TestRequest();

        // Resolver
        RequestUrlResolver resolver = new RequestUrlResolver();

        // Resolve
        String url = resolver.resolve(request);

        assertEquals("http://localhost:8080/path?key=value", url);
    }


    private static final class TestRequest implements HttpServletRequest
    {
        private final Map<String, String> headers = new HashMap<>();


        @Override
        public Object getAttribute(String name)
        {
            return null;
        }

        @Override
        public Enumeration<String> getAttributeNames()
        {
            return null;
        }

        @Override
        public String getCharacterEncoding()
        {
            return null;
        }

        @Override
        public void setCharacterEncoding(String env) throws UnsupportedEncodingException
        {
        }

        @Override
        public int getContentLength()
        {
            return 0;
        }

        @Override
        public long getContentLengthLong()
        {
            return 0;
        }

        @Override
        public String getContentType()
        {
            return null;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException
        {
            return null;
        }

        @Override
        public String getParameter(String name)
        {
            return null;
        }

        @Override
        public Enumeration<String> getParameterNames()
        {
            return null;
        }

        @Override
        public String[] getParameterValues(String name)
        {
            return null;
        }

        @Override
        public Map<String, String[]> getParameterMap()
        {
            return null;
        }

        @Override
        public String getProtocol()
        {
            return null;
        }

        @Override
        public String getScheme()
        {
            return null;
        }

        @Override
        public String getServerName()
        {
            return null;
        }

        @Override
        public int getServerPort()
        {
            return 0;
        }

        @Override
        public BufferedReader getReader() throws IOException
        {
            return null;
        }

        @Override
        public String getRemoteAddr()
        {
            return null;
        }

        @Override
        public String getRemoteHost()
        {
            return null;
        }

        @Override
        public void setAttribute(String name, Object o)
        {
        }

        @Override
        public void removeAttribute(String name)
        {
        }

        @Override
        public Locale getLocale()
        {
            return null;
        }

        @Override
        public Enumeration<Locale> getLocales()
        {
            return null;
        }

        @Override
        public boolean isSecure()
        {
            return false;
        }

        @Override
        public RequestDispatcher getRequestDispatcher(String path)
        {
            return null;
        }

        @Override
        public String getRealPath(String path)
        {
            return null;
        }

        @Override
        public int getRemotePort()
        {
            return 0;
        }

        @Override
        public String getLocalName()
        {
            return null;
        }

        @Override
        public String getLocalAddr()
        {
            return null;
        }

        @Override
        public int getLocalPort()
        {
            return 0;
        }

        @Override
        public ServletContext getServletContext()
        {
            return null;
        }

        @Override
        public AsyncContext startAsync() throws IllegalStateException
        {
            return null;
        }

        @Override
        public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException
        {
            return null;
        }

        @Override
        public boolean isAsyncStarted()
        {
            return false;
        }

        @Override
        public boolean isAsyncSupported()
        {
            return false;
        }

        @Override
        public AsyncContext getAsyncContext()
        {
            return null;
        }

        @Override
        public DispatcherType getDispatcherType()
        {
            return null;
        }

        @Override
        public String getAuthType()
        {
            return null;
        }

        @Override
        public Cookie[] getCookies()
        {
            return null;
        }

        @Override
        public long getDateHeader(String name)
        {
            return 0;
        }

        @Override
        public String getHeader(String name)
        {
            return headers.get(name.toLowerCase());
        }

        public TestRequest addHeader(String name, String value)
        {
            headers.put(name.toLowerCase(), value);

            return this;
        }

        @Override
        public Enumeration<String> getHeaders(String name)
        {
            return null;
        }

        @Override
        public Enumeration<String> getHeaderNames()
        {
            return null;
        }

        @Override
        public int getIntHeader(String name)
        {
            return 0;
        }

        @Override
        public String getMethod()
        {
            return null;
        }

        @Override
        public String getPathInfo()
        {
            return null;
        }

        @Override
        public String getPathTranslated()
        {
            return null;
        }

        @Override
        public String getContextPath()
        {
            return null;
        }

        @Override
        public String getQueryString()
        {
            return "key=value";
        }

        @Override
        public String getRemoteUser()
        {
            return null;
        }

        @Override
        public boolean isUserInRole(String role)
        {
            return false;
        }

        @Override
        public Principal getUserPrincipal()
        {
            return null;
        }

        @Override
        public String getRequestedSessionId()
        {
            return null;
        }

        @Override
        public String getRequestURI()
        {
            return "/path";
        }

        @Override
        public StringBuffer getRequestURL()
        {
            return new StringBuffer("http://localhost:8080/path");
        }

        @Override
        public String getServletPath()
        {
            return null;
        }

        @Override
        public HttpSession getSession(boolean create)
        {
            return null;
        }

        @Override
        public HttpSession getSession()
        {
            return null;
        }

        @Override
        public String changeSessionId()
        {
            return null;
        }

        @Override
        public boolean isRequestedSessionIdValid()
        {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromCookie()
        {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromURL()
        {
            return false;
        }

        @Override
        public boolean isRequestedSessionIdFromUrl()
        {
            return false;
        }

        @Override
        public boolean authenticate(HttpServletResponse response) throws IOException, ServletException
        {
            return false;
        }

        @Override
        public void login(String username, String password) throws ServletException
        {
        }

        @Override
        public void logout() throws ServletException
        {
        }

        @Override
        public Collection<Part> getParts() throws IOException, ServletException
        {
            return null;
        }

        @Override
        public Part getPart(String name) throws IOException, ServletException
        {
            return null;
        }

        @Override
        public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException
        {
            return null;
        }
    }
}
