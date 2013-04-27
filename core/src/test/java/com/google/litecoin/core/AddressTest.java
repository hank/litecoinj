/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.litecoin.core;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.util.Arrays;

import static org.junit.Assert.*;

public class AddressTest {
    static final NetworkParameters testParams = NetworkParameters.testNet();
    static final NetworkParameters prodParams = NetworkParameters.prodNet();

    @Test
    public void stringification() throws Exception {
        // Test a testnet address.
        Address a = new Address(testParams, Hex.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", a.toString());

        Address b = new Address(prodParams, Hex.decode("3f2ebb6c8d88e586b551303d2c29eba15518d8d1"));
        assertEquals("LQz2pJYaeqntA9BFB8rDX5AL2TTKGd5AuN", b.toString());
    }
    
    @Test
    public void decoding() throws Exception {
        Address a = new Address(testParams, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc", Utils.bytesToHexString(a.getHash160()));

        Address b = new Address(prodParams, "LQz2pJYaeqntA9BFB8rDX5AL2TTKGd5AuN");
        assertEquals("3f2ebb6c8d88e586b551303d2c29eba15518d8d1", Utils.bytesToHexString(b.getHash160()));
    }
    
    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            new Address(testParams, "this is not a valid address!");
            fail();
        } catch (WrongNetworkException e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the empty case.
        try {
            new Address(testParams, "");
            fail();
        } catch (WrongNetworkException e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            new Address(testParams, "LQz2pJYaeqntA9BFB8rDX5AL2TTKGd5AuN");
            fail();
        } catch (WrongNetworkException e) {
            // Success.
            assertEquals(e.verCode, NetworkParameters.prodNet().addressHeader);
            assertTrue(Arrays.equals(e.acceptableVersions, NetworkParameters.testNet().acceptableAddressCodes));
        } catch (AddressFormatException e) {
            fail();
        }
    }
    
    @Test
    public void getNetwork() throws Exception {
        NetworkParameters params = Address.getParametersFromAddress("LQz2pJYaeqntA9BFB8rDX5AL2TTKGd5AuN");
        assertEquals(NetworkParameters.prodNet().getId(), params.getId());
        params = Address.getParametersFromAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
        assertEquals(NetworkParameters.testNet().getId(), params.getId());
    }
}
