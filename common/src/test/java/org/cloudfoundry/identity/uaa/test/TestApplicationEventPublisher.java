/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TestApplicationEventPublisher<T extends ApplicationEvent> implements ApplicationEventPublisher {
    private final Class<T> clazz;
    private final List<T> events = new ArrayList<T>();

    public static <K extends ApplicationEvent> TestApplicationEventPublisher<K> forEventClass(Class<K> eventType) {
        return new TestApplicationEventPublisher<K>(eventType);
    }

    private TestApplicationEventPublisher(Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public void publishEvent(ApplicationEvent applicationEvent) {
        if (clazz.isAssignableFrom(applicationEvent.getClass())) {
            events.add((T) applicationEvent);
        } else {
            throw new UnsupportedOperationException(toString() + " cannot publish events of type " + applicationEvent.getClass());
        }
    }

    public int getEventCount() {
        return events.size();
    }

    public void clearEvents() {
        events.clear();
    }

    public List<T> getEvents() {
        return Collections.unmodifiableList(events);
    }

    public T getEarliestEvent() {
        if (events.size() > 0) {
            return events.get(0);
        } else {
            return null;
        }
    }

    public T getLatestEvent() {
        if (events.size() > 0) {
            return events.get(events.size() - 1);
        } else {
            return null;
        }
    }
}
