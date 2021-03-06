/*
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.iotdm.onem2m.client;

import org.opendaylight.iotdm.onem2m.core.Onem2m;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Onem2mAERequestBuilder extends Onem2mRequestPrimitiveClientBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(Onem2mAERequestBuilder.class);

    private ResourceAEBuilder b;

    public Onem2mAERequestBuilder() {
        super();
        b = new ResourceAEBuilder();

        // set dome default parameters that all internal apps have no need to set but the core expects
        setFrom("onem2m://Onem2mAERequest");
        setRequestIdentifier("Onem2mAERequest-rqi");
        setProtocol(Onem2m.Protocol.NATIVEAPP);
        setContentFormat(Onem2m.ContentFormat.JSON);
        setNativeAppName("Onem2mAERequest");
    }

    public Onem2mAERequestBuilder setAppName(String value) {
        b.setAppName(value);
        return this;
    }

    public Onem2mAERequestBuilder setAppId(String value) {
        b.setAppId(value);
        return this;
    }

    public Onem2mAERequestBuilder setAEId(String value) {
        b.setAEId(value);
        return this;
    }

    public Onem2mAERequestBuilder setRequestReachability(Boolean value) {
        b.setRequestReachability(value);
        return this;
    }

    public Onem2mAERequestBuilder setOntologyRef(String value) {
        b.setOntologyRef(value);
        return this;
    }

    public Onem2mRequestPrimitiveClient build() {
        if (!isDelete) {
            String resourceString = b.build();
            setPrimitiveContent(resourceString);
        }
        if (isCreate) {
            setResourceType(Onem2m.ResourceType.AE);
        }
        return super.build();
    }
}
