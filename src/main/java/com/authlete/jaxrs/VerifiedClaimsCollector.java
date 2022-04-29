/*
 * Copyright (C) 2022 Authlete, Inc.
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


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import com.authlete.common.dto.StringArray;
import com.authlete.common.util.Utils;


/**
 * Utility to collect verified claims by using an SPI implementation.
 *
 * <p>
 * This class implements the complex logic of how to call the method
 * provided by the SPI implementation so that the SPI implementation can
 * focus on building a new dataset that satisfies conditions of a
 * {@code "verified_claims"} request without needing to know how to
 * interact with Authlete APIs.
 * </p>
 *
 * @since 2.43
 */
class VerifiedClaimsCollector
{
    // Keys that appear in JSON
    private static final String KEY_VERIFIED_CLAIMS = "verified_claims";
    private static final String KEY_CLAIMS          = "claims";


    private final BiFunction<String, Object, Object> mVerifiedClaimsGetter;


    public VerifiedClaimsCollector(BiFunction<String, Object, Object> getter)
    {
        mVerifiedClaimsGetter = getter;
    }


    public Map<String, Object> collect(
            Map<String, Object> claims, String subject, String claimsRequest)
    {
        Object verifiedClaimsRequest = extractVerifiedClaimsRequest(claimsRequest);

        if (verifiedClaimsRequest == null)
        {
            // No need to collect verified claims because the authorization
            // request does not contain "verified_claims".
            //
            // The set of claims that will appear in the ID token or the
            // userinfo response is not changed here.
            return claims;
        }

        // Use the getter to collect values of verified claims.
        Object verifiedClaimsValue =
                mVerifiedClaimsGetter.apply(subject, verifiedClaimsRequest);

        // If the getter did not build a value of "verified_claims".
        if (verifiedClaimsValue == null)
        {
            // "verified_claims" won't be included in the ID token or the
            // userinfo response.
            return claims;
        }

        // If the API caller did not pass the "claims" request parameter
        // to the Authlete API (/api/auth/authorization/issue API or
        // /api/auth/userinfo/issue API).
        if (claims == null)
        {
            // Create a holder that contains "verified_claims".
            claims = new HashMap<>();
        }

        // Embed "verified_claims" in the ID token or the userinfo response.
        claims.put(KEY_VERIFIED_CLAIMS, verifiedClaimsValue);

        return claims;
    }


    private Object extractVerifiedClaimsRequest(String claimsRequest)
    {
        // 'claimsRequest' here represents the content of "id_token"
        // or "userinfo" in the "claims" request parameter of an
        // authorization request.
        if (claimsRequest == null || claimsRequest.length() == 0)
        {
            // "verified_claims" appears under "id_token" or "userinfo".
            // If the container is missing, "verified_claims" cannot be
            // present.
            return null;
        }

        // Extract the value of "verified_claims". The value is one of
        // (1) a Map instance, (2) a List instance, or (3) null.
        return Utils.fromJson(claimsRequest, Map.class).get(KEY_VERIFIED_CLAIMS);
    }


    public List<Map<String, Object>> collectForTx(
            String subject, String claimsRequest,
            StringArray[] requestedVerifiedClaimsForTx)
    {
        // If no verified claims are requested for transformed claims.
        // (= if the authorization request contains no transformed claims.)
        if (requestedVerifiedClaimsForTx == null)
        {
            // No need to collect verified claims.
            return null;
        }

        Object verifiedClaimsRequest = extractVerifiedClaimsRequest(claimsRequest);

        // 'verifiedClaimsRequest' is either List or Map.
        // Convert it to a list of Map instances in either case.
        List<Map<String, Object>> requests = toMapList(verifiedClaimsRequest);
        if (requests == null)
        {
            // The authorization request did not contain "verified_claims", or
            // something unexpected ('verifiedClaimsRequest' is neither List
            // nor Map) happened.
            return null;
        }

        // The number of elements in 'requestedVerifiedClaimsForTx' is equal to
        // the number of elements in 'requests' (which came from "verified_claims"
        // in the "claims" request parameter of the authorization request) because
        // Authlete's /api/auth/authorization API has prepared the array so.
        // Here we confirm it.
        if (requestedVerifiedClaimsForTx.length != requests.size())
        {
            // Unexpected.
            return null;
        }

        List<Map<String, Object>> verifiedClaimsForTxList = new ArrayList<>();

        int size = requests.size();

        for (int i = 0; i < size; i++)
        {
            // If the type of "verified_claims" in the authorization request is
            // a JSON array, 'request' here is the element at the index of the
            // array. On the other hand, if the type of "verified_claims" is a
            // JSON object, 'request' is the value of "verified_claims".
            Map<String, Object> request = requests.get(i);

            // Names of verified claims that are referenced by transformed claims.
            // If the 'request' does not contain transformed claims, the element
            // in 'requestedVerifiedClaimsForTx' (which corresponds to the request)
            // does not contain names of verified claims. In the case, 'claimNames'
            // here becomes null.
            String[] claimNames = extractArray(requestedVerifiedClaimsForTx[i]);

            // Get a Map that contains verified claims which are referenced by
            // the transformed claims. The Map may become null when no dataset
            // is available that satisfies conditions of the request. Note that
            // even when 'claimNames' is null, a non-null value (an empty Map)
            // is returned if a dataset that satisfies conditions of the request
            // is available.
            Map<String, Object> claims =
                    getVerifiedClaimsForTx(subject, request, claimNames);

            // If, at least, a dataset that satisfied conditions of the request
            // was built successfully in getVerifiedClaimsForTx().
            if (claims != null)
            {
                verifiedClaimsForTxList.add(claims);
            }
        }

        if (verifiedClaimsForTxList.size() == 0)
        {
            return null;
        }

        return verifiedClaimsForTxList;
    }


    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> toMapList(Object object)
    {
        // If the type of the object is List.
        if (object instanceof List)
        {
            // Just cast the object to List.
            return (List<Map<String, Object>>)object;
        }

        // If the type of the object is Map.
        if (object instanceof Map)
        {
            // Create a List which includes the object as the only element.
            return Arrays.asList((Map<String, Object>)object);
        }

        return null;
    }


    private static String[] extractArray(StringArray stringArray)
    {
        // Get the content of stringArray.array without causing
        // NullPointerException in any case.

        if (stringArray == null)
        {
            return null;
        }

        String[] array = stringArray.getArray();

        if (array == null || array.length == 0)
        {
            return null;
        }

        return array;
    }


    @SuppressWarnings("unchecked")
    private Map<String, Object> getVerifiedClaimsForTx(
            String subject, Map<String, Object> request, String[] claimNames)
    {
        // Authlete's /auth/authorization/issue API and /api/auth/userinfo/issue
        // API recognize 'claims' and 'verifiedClaimsForTx' request parameters.
        //
        // The format of the 'claims' parameter is JSON and it may contain
        // "verified_claims". The value of "verified_claims" is either a JSON
        // object or a JSON array.
        //
        // The 'verifiedClaimsForTx' is a string array. The format of the
        // elements in the array is JSON. The JSON should contain verified
        // claims which are referenced by transformed claims.
        //
        // When the type of "verified_claims" is a JSON array, the Authlete
        // APIs expect that the number of elements in 'verifiedClaimsForTx'
        // (when it is not null) is equal to the number of elements in the
        // "verified_claims".
        //
        // When the type of "verified_claims" is a JSON object, the Authlete
        // APIs expect that the number of elements in 'verifiedClaimsForTx'
        // (when it is not null) is 1.
        //
        // Keep the above in mind when you read the code below.

        // If names of verified claims are not specified. This means that
        // the request does not contain transformed claims.
        if (claimNames == null)
        {
            // If a dataset that satisfies conditions of the request is available.
            // Conditions here are ones specified by "verified_claims/verification".
            if (mVerifiedClaimsGetter.apply(subject, request) != null)
            {
                // The request does not contain transformed claims but the element
                // that corresponds to the request should not be omitted from the
                // 'verifiedClaimsForTx' array. It is because that "verified_claims"
                // will contain an element that corresponds to the request.
                return Collections.emptyMap();
            }
            else
            {
                // A dataset that satisfies conditions of the request is unavailable.
                // The "verified_claims" array in the ID token or the userinfo
                // response will not include an element that corresponds to the
                // request. Therefore, the 'verifiedClaimsForTx' array should
                // not include an element that corresponds to the request, either.
                return null;
            }
        }

        // The current value of "claims" in the request.
        // The value will be restored later.
        boolean containsClaims = request.containsKey(KEY_CLAIMS);
        Object  originalClaims = request.get(KEY_CLAIMS);

        // Because of the data minimization policy, claims are omitted if
        // they are not requested explicitly. Therefore, it is necessary
        // to put the names of indirectly-referenced verified claims.
        //
        // We prepare a map that represents "claims" and contains names of
        // verified claims that are referenced by the transformed claims.
        //
        Map<String, Object> claims = new HashMap<>();

        // Put the claim names in "claims".
        for (String name : claimNames)
        {
            // Put the name of the verified claim.
            claims.put(name, null);
        }

        // Overwrite "claims" in the request.
        request.put(KEY_CLAIMS, claims);

        // Build a new dataset that contains the indirectly-referenced verified
        // claims. Note that conditions under "verification" in the 'request'
        // have not been changed, so filtering conditions specified under
        // "verification" still function.
        //
        // When the type of the second argument is Map, the apply() method of
        // 'mVerifiedClaimsGetter' should return a Map (not a List).
        Map<String, Object> dataset =
                (Map<String, Object>)mVerifiedClaimsGetter.apply(subject, request);

        // Restore the previous value of "claims".
        if (containsClaims)
        {
            request.put(KEY_CLAIMS, originalClaims);
        }
        else
        {
            request.remove(KEY_CLAIMS);
        }

        // If a dataset that meets conditions of the request is unavailable.
        if (dataset == null)
        {
            // The 'verifiedClaimsForTx' array should not have an element that
            // corresponds to the request.
            return null;
        }

        // The content of "claims" in the dataset is what we want.
        claims = (Map<String, Object>)dataset.get(KEY_CLAIMS);

        if (claims == null)
        {
            // Still, the 'verifiedClaimsForTx' should include an element
            // that corresponds to the request.
            return Collections.emptyMap();
        }

        return claims;
    }
}
