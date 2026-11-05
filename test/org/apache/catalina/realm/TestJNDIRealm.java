/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.realm;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.juli.logging.LogFactory;
import org.apache.naming.NameParserImpl;
import org.apache.tomcat.unittest.TesterContext;
import org.apache.tomcat.util.security.MD5Encoder;
import org.easymock.EasyMock;

public class TestJNDIRealm {

    private static final String ALGORITHM = "MD5";

    private static final String USER = "test-user";
    private static final String USER_DN = "cn=" + USER + ",ou=people,dc=example,dc=com";
    private static final String PASSWORD = "test-password";
    private static final String REALM = "test-realm";

    private static final String NONCE = "test-nonce";
    private static final String HA2 = "test-md5a2";
    public static final String USER_PASSWORD_ATTR = "test-pwd";

    private static MessageDigest md5Helper;

    @BeforeClass
    public static void setupClass() throws Exception {
        md5Helper = MessageDigest.getInstance(ALGORITHM);
    }

    @Test
    public void testAuthenticateWithoutUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertNull(principal);
    }

    @Test
    public void testAuthenticateWithUserPassword() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(PASSWORD);
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertTrue(principal instanceof GenericPrincipal);
        Assert.assertEquals(PASSWORD, ((GenericPrincipal)principal).getPassword());
    }

    @Test
    public void testAuthenticateWithUserPasswordAndCredentialHandler() throws Exception {
        // GIVEN
        JNDIRealm realm = buildRealm(ha1());
        realm.setCredentialHandler(buildCredentialHandler());
        realm.setUserPassword(USER_PASSWORD_ATTR);

        // WHEN
        String expectedResponse =
                MD5Encoder.encode(md5Helper.digest((ha1() + ":" + NONCE + ":" + HA2).getBytes()));
        Principal principal =
                realm.authenticate(USER, expectedResponse, NONCE, null, null, null, REALM, HA2);

        // THEN
        Assert.assertTrue(principal instanceof GenericPrincipal);
        Assert.assertEquals(ha1(), ((GenericPrincipal)principal).getPassword());
    }


    @Test
    public void testBindAsUserWithAuthenticationNone() throws Exception {
        doTestBindAsUser("none");
    }


    @Test
    public void testBindAsUserWithAuthenticationExternal() throws Exception {
        doTestBindAsUser("EXTERNAL");
    }


    @Test
    public void testBindAsUserWithAuthenticationSimple() throws Exception {
        doTestBindAsUser("simple");
    }


    @Test
    public void testBindAsUserWithoutAuthentication() throws Exception {
        doTestBindAsUser(null);
    }


    private void doTestBindAsUser(String authentication) throws Exception {
        // GIVEN
        JNDIRealm realm = new JNDIRealm();
        realm.containerLog = LogFactory.getLog(TestJNDIRealm.class);
        realm.setAuthentication(authentication);

        Hashtable<Object,Object> environment = new Hashtable<>();
        if (authentication != null) {
            environment.put(javax.naming.Context.SECURITY_AUTHENTICATION, authentication);
        }
        DirContext dirContext = createBindDirContext(environment);
        JNDIRealm.User user = new JNDIRealm.User(USER, USER_DN, null, null, null);

        // WHEN / THEN
        // A wrong password must never be accepted, whatever authentication
        // mechanism has been configured for the realm's own connection
        Assert.assertFalse(realm.bindAsUser(dirContext, user, "wrong-" + PASSWORD));
        assertEnvironmentRestored(authentication, environment);

        Assert.assertTrue(realm.bindAsUser(dirContext, user, PASSWORD));
        assertEnvironmentRestored(authentication, environment);
    }


    private void assertEnvironmentRestored(String authentication,
            Hashtable<Object,Object> environment) {
        Assert.assertEquals(authentication,
                environment.get(javax.naming.Context.SECURITY_AUTHENTICATION));
        Assert.assertNull(environment.get(javax.naming.Context.SECURITY_PRINCIPAL));
        Assert.assertNull(environment.get(javax.naming.Context.SECURITY_CREDENTIALS));
    }


    /*
     * Simulates the bind behaviour of an LDAP server / the JNDI LDAP provider:
     * a simple bind validates the provided DN and password whereas an
     * anonymous bind ("none") or a SASL EXTERNAL bind ignores the provided
     * password.
     */
    private DirContext createBindDirContext(final Hashtable<Object,Object> environment) {
        InvocationHandler handler = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args)
                    throws Throwable {
                String name = method.getName();
                if ("addToEnvironment".equals(name)) {
                    return environment.put(args[0], args[1]);
                } else if ("removeFromEnvironment".equals(name)) {
                    return environment.remove(args[0]);
                } else if ("getEnvironment".equals(name)) {
                    return environment.clone();
                } else if ("getAttributes".equals(name) && args.length == 2 &&
                        "".equals(args[0])) {
                    Object principal = environment.get(javax.naming.Context.SECURITY_PRINCIPAL);
                    Object credentials =
                            environment.get(javax.naming.Context.SECURITY_CREDENTIALS);
                    Object mechanism =
                            environment.get(javax.naming.Context.SECURITY_AUTHENTICATION);
                    if (mechanism == null) {
                        mechanism = principal == null ? "none" : "simple";
                    }
                    if ("simple".equals(mechanism) && !(USER_DN.equals(principal) &&
                            PASSWORD.equals(credentials))) {
                        throw new AuthenticationException("Invalid credentials");
                    }
                    return new BasicAttributes();
                }
                throw new UnsupportedOperationException(name);
            }
        };
        return (DirContext) Proxy.newProxyInstance(TestJNDIRealm.class.getClassLoader(),
                new Class<?>[] { DirContext.class }, handler);
    }


    private JNDIRealm buildRealm(String password) throws javax.naming.NamingException,
            NoSuchFieldException, IllegalAccessException, LifecycleException {
        Context context = new TesterContext();
        JNDIRealm realm = new JNDIRealm();
        realm.setContainer(context);
        realm.setUserSearch("");

        // Usually everything is created in create() but that's not the case here
        Field field = JNDIRealm.class.getDeclaredField("singleConnection");
        field.setAccessible(true);
        Field field2 = JNDIRealm.JNDIConnection.class.getDeclaredField("context");
        field2.setAccessible(true);
        field2.set(field.get(realm), mockDirContext(mockSearchResults(password)));

        realm.start();

        return realm;
    }

    private MessageDigestCredentialHandler buildCredentialHandler()
            throws NoSuchAlgorithmException {
        MessageDigestCredentialHandler credentialHandler = new MessageDigestCredentialHandler();
        credentialHandler.setAlgorithm(ALGORITHM);
        return credentialHandler;
    }

    private NamingEnumeration<SearchResult> mockSearchResults(String password)
            throws NamingException {
        @SuppressWarnings("unchecked")
        NamingEnumeration<SearchResult> searchResults =
                EasyMock.createNiceMock(NamingEnumeration.class);
        EasyMock.expect(Boolean.valueOf(searchResults.hasMore()))
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE)
                .andReturn(Boolean.TRUE)
                .andReturn(Boolean.FALSE);
        EasyMock.expect(searchResults.next())
                .andReturn(new SearchResult("ANY RESULT", "",
                        new BasicAttributes(USER_PASSWORD_ATTR, password)))
                .times(2);
        EasyMock.replay(searchResults);
        return searchResults;
    }

    private DirContext mockDirContext(NamingEnumeration<SearchResult> namingEnumeration)
            throws NamingException {
        DirContext dirContext = EasyMock.createNiceMock(InitialDirContext.class);
        EasyMock.expect(dirContext.search(EasyMock.anyString(), EasyMock.anyString(),
                        EasyMock.anyObject(SearchControls.class)))
                .andReturn(namingEnumeration)
                .times(2);
        EasyMock.expect(dirContext.getNameParser(""))
                .andReturn(new NameParserImpl()).times(2);
        EasyMock.expect(dirContext.getNameInNamespace())
                .andReturn("ANY NAME")
                .times(2);
        EasyMock.replay(dirContext);
        return dirContext;
    }

    private String ha1() {
        String a1 = USER + ":" + REALM + ":" + PASSWORD;
        return MD5Encoder.encode(md5Helper.digest(a1.getBytes()));
    }
}
