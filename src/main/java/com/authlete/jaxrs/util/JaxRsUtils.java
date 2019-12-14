/*
 * Copyright (C) 2017-2019 Authlete, Inc.
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
package com.authlete.jaxrs.util;


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Map;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;


/**
 * JAX-RS Utilities.
 *
 * @since 2.6
 */
public class JaxRsUtils
{
    /**
     * Create a {@code Map<TKey, TValue>} instance from a
     * {@code Map<TKey, TValue[]} instance.
     *
     * @param data
     *         Input data.
     *
     * @return
     *         A new instance which contains all the entries
     *         in the input data. If the input data is {@code null}
     *         or empty, an empty {@code MultivaluedMap} instance
     *         is returned.
     */
    public static <TKey, TValue> MultivaluedMap<TKey, TValue>
            createMultivaluedMap(Map<TKey, TValue[]> data)
    {
        MultivaluedMap<TKey, TValue> target
            = new MultivaluedHashMap<TKey, TValue>();

        return putAll(target, data);
    }


    /**
     * Put all entries in a {@code Map<TKey, TValue[]>} instance
     * into an existing {@code MultivaluedMap<TKey, TValue>}.
     *
     * @param target
     *         Target {@code MultivaluedMap} instance.
     *
     * @param data
     *         Input data.
     *
     * @return
     *         The object given as {@code target}.
     */
    public static <TKey, TValue> MultivaluedMap<TKey, TValue>
            putAll(MultivaluedMap<TKey, TValue> target, Map<TKey, TValue[]> data)
    {
        if (target == null || data == null)
        {
            return target;
        }

        for (Map.Entry<TKey, TValue[]> entry : data.entrySet())
        {
            target.addAll(entry.getKey(), entry.getValue());
        }

        return target;
    }


    /**
     * Convert a string in the {@code application/x-www-form-urlencoded} format
     * into an instance of {@link MultivaluedMap}{@code <String, String>}.
     *
     * @param input
     *         A string in the format of {@code application/x-www-form-urlencoded}.
     *
     * @return
     *         An instance of {@link MultivaluedMap}{@code <String, String>} that
     *         represents the result of parsing the input string.
     */
    public static MultivaluedMap<String, String> parseFormUrlencoded(String input)
    {
        MultivaluedMap<String, String> parameters = new MultivaluedHashMap<String, String>();

        if (input == null || input.length() == 0)
        {
            return parameters;
        }

        // If the first letter is '?'. This happens when the service implementation
        // uses System.Uri.Query.
        if (input.charAt(0) == '?')
        {
            // Remove the first letter.
            input = input.substring(1);
        }

        for (String parameter : input.split("&"))
        {
            String[] pair = parameter.split("=", 2);

            if (pair == null || pair.length == 0 || pair[0].length() == 0)
            {
                continue;
            }

            String key   = urlDecode(pair[0]);
            String value = (pair.length == 2) ? urlDecode(pair[1]) : "";

            parameters.add(key, value);
        }

        return parameters;
    }


    private static String urlDecode(String input)
    {
        try
        {
            return URLDecoder.decode(input, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            return input;
        }
    }
}
