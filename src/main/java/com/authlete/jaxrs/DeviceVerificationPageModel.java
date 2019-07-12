/*
 * Copyright (C) 2019 Authlete, Inc.
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


import java.io.Serializable;
import com.authlete.common.types.User;


/**
 * Model class to hold data which are referred to in an verification page in device
 * flow.
 *
 * <p>
 * Feel free to extend this class as necessary.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public class DeviceVerificationPageModel implements Serializable
{
    private static final long serialVersionUID = 1L;


    /**
     * The login ID that should be used as the initial value for the
     * login ID field in the authorization page.
     */
    private String loginId;


    /**
     * The user code inputed by the user.
     */
    private String userCode;


    /**
     * Currently logged in user, could be null if no user is logged in.
     */
    private User user;


    /**
     * The notification.
     */
    private String notification;


    /**
     * The default constructor with default values.
     */
    public DeviceVerificationPageModel()
    {
    }


    /**
     * Create an {@link DeviceVerificationPageModel} instance using given parameters.
     *
     * @param loginId
     *         The login ID that should be used as the initial value for the login
     *         ID field in the verification page.
     *
     * @param userCode
     *         The user code that should be used as the initial value for the user
     *         code field in the verification page.
     *
     * @param user
     *         The currently logged in user.
     *
     * @param notification
     *         The notification that should be shown in the verification page.
     */
    public DeviceVerificationPageModel(String loginId, String userCode, User user, String notification)
    {
        this.loginId      = loginId;
        this.userCode     = userCode;
        this.user         = user;
        this.notification = notification;
    }


    /**
     * Get the login ID which should be set to the login ID field
     * in the verification page as the initial value.
     *
     * @return
     *         The initial value of the login ID.
     */
    public String getLoginId()
    {
        return loginId;
    }


    /**
     * Set the login ID which should be set to the login ID field
     * in the verification page as the initial value.
     *
     * @param loginId
     *         The initial value of the login ID.
     *
     * @return
     *         {@code this} object.
     */
    public DeviceVerificationPageModel setLoginId(String loginId)
    {
        this.loginId = loginId;

        return this;
    }


    /**
     * Get the user code should be set to the user code field
     * in the verification page as the initial value.
     *
     * @return
     *         The initial value of the user code.
     */
    public String getUserCode()
    {
        return userCode;
    }


    /**
     * Set the user code should be set to the user code field
     * in the verification page as the initial value.
     *
     * @param userCode
     *         The initial value of the user code.
     *
     * @return
     *         {@code this} object.
     */
    public DeviceVerificationPageModel setUserCode(String userCode)
    {
        this.userCode = userCode;

        return this;
    }


    /**
     * Get the currently logged in user, could be null if no user is logged in.
     *
     * @return
     *         The currently logged in user.
     */
    public User getUser()
    {
        return user;
    }


    /**
     * Set the currently logged in user.
     *
     * @param user
     *            The currently logged in user.
     * @return
     *         {@code this} object.
     */
    public DeviceVerificationPageModel setUser(User user)
    {
        this.user = user;

        return this;
    }


    /**
     * Get the notification that should be shown in the verification page.
     *
     * @return
     *         The notification that should be shown in the verification page.
     */
    public String getNotification()
    {
        return notification;
    }


    /**
     * Set the notification that should be shown in the verification page.
     *
     * @param notification
     *         The notification that should be shown in the verification page.
     *
     * @return
     *         {@code this} object.
     */
    public DeviceVerificationPageModel setNotification(String notification)
    {
        this.notification = notification;

        return this;
    }
}
