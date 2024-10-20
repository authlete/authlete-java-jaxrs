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


import javax.servlet.http.HttpServletRequest;
import com.authlete.http.ForwardedElement;
import com.authlete.http.ForwardedFieldValue;


/**
 * A utility to resolve the original request URL.
 *
 * <p>
 * The {@link #resolve(HttpServletRequest)} method follows the logic below,
 * in this order, to resolve the original request URL.
 * </p>
 *
 * <ol>
 * <li><p><b>Resolve by configuration</b></p><br>
 *
 * <p>
 * If fixed values for the scheme and host have been set using the
 * {@link #setScheme(String)} and {@link #setHost(String)} methods, the
 * original request URL is reconstructed using the Request URL Construction
 * logic (explained later) with the {@link HttpServletRequest} instance and
 * the specified scheme and host.
 * </p>
 * <br>
 *
 * <li><p><b>Resolve by an HTTP field containing the request URL</b></p><br>
 *
 * <p>
 * If the name of a custom HTTP field containing the original request URL
 * has been set using {@link #setUrlFieldName(String)} and the request
 * includes this HTTP field, the field's value is regarded as the original
 * request URL.
 * </p>
 * <br>
 *
 * <p>
 * If the name of such a custom HTTP field has not been provided,
 * {@code X-Forwarded-URL} is used as the default name. If the request
 * includes the {@code X-Forwarded-URL} HTTP field, its value is regarded
 * as the original request URL.
 * </p>
 * <br>
 *
 * <li><p><b>Resolve by the {@code Forwarded} HTTP Field</b></p><br>
 *
 * <p>
 * If the request includes the {@code Forwarded} HTTP field (<a href=
 * "https://www.rfc-editor.org/rfc/rfc7239.html">RFC 7239: Forwarded HTTP
 * Extension</a>) and the first "forwarded element" in the field includes
 * both the {@code proto} and {@code host} parameters, the original request
 * URL is reconstructed using the Request URL Construction logic with the
 * {@link HttpServletRequest} instance and the scheme specified by the
 * {@code proto} parameter and the host specified by the {@code host}
 * parameter.
 * </p>
 * <br>
 *
 * <li><p><b>Resolve by de facto HTTP Fields</b></p><br>
 *
 * <p>
 * If the scheme and the host can be determined by using de facto HTTP
 * fields such as {@code X-Forwarded-Host} and {@code X-Forwarded-Proto},
 * the original request URL is reconstructed using the Request URL
 * Construction logic with the {@link HttpServletRequest} instance and
 * the determined scheme and host.
 * </p>
 * <br>
 *
 * <p>
 * To be exact, the host and scheme are determined by the following logic.
 * </p>
 * <br>
 *
 * <p>
 * The host is determined by the {@code X-Forwarded-Host} HTTP field.
 * </p>
 * <br>
 *
 * <p>
 * The scheme is determined by the following logic in this order.
 * </p>
 * <br>
 *
 * <ol>
 * <li>If the {@code X-Forwarded-Proto} HTTP field is included, its value is
 * used as the scheme.
 * <li>If the {@code X-Forwarded-Protocol} HTTP field is included, its value
 * is used as the scheme.
 * <li>If the {@code X-Url-Scheem} HTTP field is included, its value is used
 * as the scheme.
 * <li>If the {@code X-Forwarded-Ssl} HTTP field is included and its value
 * is {@code on}, {@code https} is used as the scheme. If the HTTP field is
 * included but its value is not {@code on}, {@code http} is used as the scheme.
 * <li>If the {@code Front-End-Https} HTTP field is included and its value
 * is {@code on}, {@code https} is used as the scheme. If the HTTP field is
 * included but its value is not {@code on}, {@code http} is used as the scheme.
 * </ol>
 * <br>
 *
 * <li><p><b>Resolve by HttpServletRequest</b></p><br>
 *
 * <p>
 * The original request URL is reconstructed by calling the {@link
 * HttpServletRequest#getRequestURL() getRequestURL()} and {@link
 * HttpServletRequest#getQueryString() getQueryString()} methods as follows.
 * A question mark ({@code ?}) is added only if the query string is not null.
 * </p>
 *
 * <pre>
 * {@link HttpServletRequest#getRequestURL()}?{@link HttpServletRequest#getQueryString()}
 * </pre>
 *
 * </ol>
 *
 * <p><b>Request URL Construction logic</b></p>
 *
 * <blockquote>
 * <p>
 * This logic accepts an {@link HttpServletRequest} instance, a scheme and a
 * host as input. These are used to reconstruct the original request URL as
 * follows. A question mark ({@code ?}) is added only if the query string is
 * not null.
 * </p>
 *
 * <pre>
 * {scheme}://{host}{@link HttpServletRequest#getRequestURI()}?{@link HttpServletRequest#getQueryString()}
 * </pre>
 *
 * <p>
 * Note that if the reverse proxy has modified the path or query string, this
 * logic cannot reconstruct the original request URL.
 * </p>
 *
 * <p>
 * The implementation of this logic returns null if either the scheme or host,
 * or both, are null, meaning that the next resolution logic will be attempted.
 * For example, if the first forwarded element in the {@code Forwarded} HTTP field
 * does not include the {@code proto} parameter, the resolution logic based on the
 * {@code Forwarded} HTTP field will return null, and the next resolution logic
 * (that uses de facto HTTP fields) will be attempted.
 * </p>
 * <br>
 * </blockquote>
 *
 * <p><b>{@code X-Forwarded-URL} setting</b></p>
 *
 * <blockquote>
 * <p>
 * The following example shows how to set up {@code X-Forwarded-URL} in
 * <a href="https://nginx.org/">NGINX</a>.
 * </p>
 *
 * <pre>
 * proxy_set_header X-Forwarded-URL $scheme://$host$request_uri;
 * </pre>
 * </blockquote>
 *
 * @since 2.81
 */
public class RequestUrlResolver
{
    /**
     * The default name of the HTTP field whose value represents the original
     * request URL.
     */
    private static final String DEFAULT_URL_FIELD_NAME = "X-Forwarded-URL";


    private String scheme;
    private String host;
    private String urlFieldName;


    /**
     * Get the scheme assigned to this instance as a fixed value.
     * This value is used when specified along with a host.
     *
     * @return
     *         The scheme assigned to this instance.
     */
    public String getScheme()
    {
        return scheme;
    }


    /**
     * Set a scheme as a fixed value.
     * This value is used when specified along with a host.
     *
     * @param scheme
     *         A scheme such as "https".
     *
     * @return
     *         {@code this} instance.
     */
    public RequestUrlResolver setScheme(String scheme)
    {
        this.scheme = scheme;

        return this;
    }


    /**
     * Get the host assigned to this instance as a fixed value.
     * This value is used when specified along with a scheme.
     *
     * @return
     *         The host assigned to this instance.
     */
    public String getHost()
    {
        return host;
    }


    /**
     * Set a host as a fixed value.
     * This value is used when specified along with a scheme.
     *
     * @param host
     *         A host such as "example.com".
     *
     * @return
     *         {@code this} instance.
     */
    public RequestUrlResolver setHost(String host)
    {
        this.host = host;

        return this;
    }


    /**
     * Get the name of the HTTP field whose value represents the original
     * request URL. If this property is not set, the default value,
     * {@code "X-Forwarded-URL"}, is used.
     *
     * @return
     *         The name of the HTTP field whose value represents the original
     *         request URL.
     */
    public String getUrlFieldName()
    {
        return urlFieldName;
    }


    /**
     * Set the name of the HTTP field whose value represents the original
     * request URL. If this property is not set, the default value,
     * {@code "X-Forwarded-URL"}, is used.
     *
     * @param name
     *         The name of the HTTP field whose value represents the original
     *         request URL.
     *
     * @return
     *         {@code this} object.
     */
    public RequestUrlResolver setUrlFieldName(String name)
    {
        this.urlFieldName = name;

        return this;
    }


    /**
     * Resolve the original request URL.
     *
     * @param request
     *         An HTTP request.
     *
     * @return
     *         The resolved original request URL.
     */
    public String resolve(HttpServletRequest request)
    {
        // By the configured scheme and host.
        String url = resolveByConfiguration(request);
        if (url != null)
        {
            return url;
        }

        // By a custom HTTP field whose value represents the original request URL.
        url = resolveByUrlField(request);
        if (url != null)
        {
            return url;
        }

        // By the 'Forwarded' HTTP field (RFC 7239: Forwarded HTTP Extension).
        url = resolveByForwardedField(request);
        if (url != null)
        {
            return url;
        }

        // By the de facto standard HTTP fields such as 'X-Forwarded-Host'.
        url = resolveByDeFactoFields(request);
        if (url != null)
        {
            return url;
        }

        // By information in the HttpServletRequest instance.
        return resolveByRequest(request);
    }


    private String resolveByConfiguration(HttpServletRequest request)
    {
        // The scheme and host that have been set to this RequestUrlResolver instance.
        String scheme = getScheme();
        String host   = getHost();

        // Reconstruct the original request URL by the Request URL Construction logic.
        return reconstructOriginalRequestUrl(request, scheme, host);
    }


    private String resolveByUrlField(HttpServletRequest request)
    {
        // The name of the HTTP field that includes the original request URL.
        String fieldName = getUrlFieldName();

        // If this RequestUrlResolver instance has not been given any HTTP field name.
        if (fieldName == null)
        {
            // Use the default field name.
            fieldName = DEFAULT_URL_FIELD_NAME;
        }

        // The value of the HTTP field is expected to represent the original request URL.
        return request.getHeader(fieldName);
    }


    private static String resolveByForwardedField(HttpServletRequest request)
    {
        // The value of the 'Forwarded' HTTP field.
        String fieldValue = request.getHeader("Forwarded");
        if (fieldValue == null)
        {
            return null;
        }

        ForwardedFieldValue ffv;

        try
        {
            // Parse the value of the 'Forwarded' HTTP field.
            ffv = ForwardedFieldValue.parse(fieldValue);
        }
        catch (RuntimeException cause)
        {
            // The value of the 'Forwarded' HTTP field is malformed.
            return null;
        }

        // The first 'forwarded element'.
        ForwardedElement fe = ffv.get(0);

        // The scheme and host. These may be unavailable.
        String scheme = fe.getProto();
        String host   = fe.getHost();

        // Reconstruct the original request URL by the Request URL Construction logic.
        return reconstructOriginalRequestUrl(request, scheme, host);
    }


    private static String resolveByDeFactoFields(HttpServletRequest request)
    {
        // Resolve the scheme using 'X-Forwarded-Proto' and possibly other HTTP fields.
        String scheme = resolveSchemeByFields(request);

        // The value of the 'X-Forwarded-Host' HTTP field.
        String host = request.getHeader("X-Forwarded-Host");

        // Reconstruct the original request URL by the Request URL Construction logic.
        return reconstructOriginalRequestUrl(request, scheme, host);
    }


    private static String resolveByRequest(HttpServletRequest request)
    {
        // The request URL without parameters.
        StringBuffer sb = request.getRequestURL();

        // The query string. This may be null.
        String qs = request.getQueryString();

        // Append "?{query-string}" if a query string is available,
        // and convert the buffer to a string.
        return appendQueryStringIfAvailable(sb, qs);
    }


    private static String resolveSchemeByFields(HttpServletRequest request)
    {
        // X-Forwarded-Proto
        String scheme = request.getHeader("X-Forwarded-Proto");
        if (scheme != null)
        {
            return scheme;
        }

        // X-Forwarded-Protocol
        scheme = request.getHeader("X-Forwarded-Protocol");
        if (scheme != null)
        {
            return scheme;
        }

        // X-Url-Scheme
        scheme = request.getHeader("X-Url-Scheme");
        if (scheme != null)
        {
            return scheme;
        }

        // X-Forwarded-Ssl
        String mode = request.getHeader("X-Forwarded-Ssl");
        if (mode != null)
        {
            return mode.equalsIgnoreCase("on") ? "https" : "http";
        }

        // Front-End-Https
        mode = request.getHeader("Front-End-Https");
        if (mode != null)
        {
            return mode.equalsIgnoreCase("on") ? "https" : "http";
        }

        return null;
    }


    private static String reconstructOriginalRequestUrl(
            HttpServletRequest request, String scheme, String host)
    {
        if (scheme == null || host == null)
        {
            return null;
        }

        // The request path. If the reverse proxy has modified the path,
        // this logic cannot reconstruct the original request URL.
        String path = request.getRequestURI();

        // The query string. If the reserve proxy has modified the query
        // string, this logic cannot reconstruct the original request URL.
        String qs = request.getQueryString();

        // "{scheme}://{host}{path}"
        StringBuffer sb = new StringBuffer()
                .append(scheme).append("://").append(host).append(path);

        // Append "?{query-string}" if a query string is available,
        // and convert the buffer to a string.
        return appendQueryStringIfAvailable(sb, qs);
    }


    private static String appendQueryStringIfAvailable(StringBuffer sb, String queryString)
    {
        if (queryString != null)
        {
            sb.append('?').append(queryString);
        }

        return sb.toString();
    }
}
