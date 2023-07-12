/*
 * Copyright (C) 2023 Authlete, Inc.
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


import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.CredentialOfferInfoRequest;
import com.authlete.common.dto.CredentialOfferInfoResponse;


public class CredentialOfferUriRequestHandler extends BaseHandler
{
    public CredentialOfferUriRequestHandler(final AuthleteApi api)
    {
        super(api);
    }


    public Response handle(final CredentialOfferInfoRequest request)
    {
        try
        {
            final CredentialOfferInfoResponse response = getApiCaller().callCredentialOfferInfo(request);
            return process(response);
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            throw unexpected("Unexpected error in CredentialOfferUriRequestHandler", t);
        }
    }


    private Response process(final CredentialOfferInfoResponse response)
    {
        // 'action' in the response denotes the next action which
        // this service implementation should take.
        CredentialOfferInfoResponse.Action action = response.getAction();

        // The content of the response to the client application.
        String content = response.getResultMessage();

        if (response.getInfo() != null)
        {
            content = response.getInfo().getCredentialOffer();
        }

        // Dispatch according to the action.
        switch (action)
        {
            case OK:
                return ResponseUtil.ok(content);

            case FORBIDDEN:
                return ResponseUtil.forbidden(content);

            case NOT_FOUND:
                return ResponseUtil.notFound(content);

            case CALLER_ERROR:
            case AUTHLETE_ERROR:
                return ResponseUtil.internalServerError(content);

            default:
                throw getApiCaller().unknownAction("/vci/offer/info", action);
        }
    }
}
