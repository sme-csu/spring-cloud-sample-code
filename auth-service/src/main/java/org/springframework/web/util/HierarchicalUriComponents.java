/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.util;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.*;
import sun.nio.cs.ThreadLocalCoders;

import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.UnaryOperator;

/**
 * Extension of {@link UriComponents} for hierarchical URIs.
 *
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @author Rossen Stoyanchev
 * @author Phillip Webb
 * @since 3.1.3
 * @see <a href="https://tools.ietf.org/html/rfc3986#section-1.2.3">Hierarchical URIs</a>
 */
@SuppressWarnings("serial")
final class HierarchicalUriComponents extends UriComponents {

    //private static final Logger logger = LoggerFactory.getLogger(Example.class);

    private static final char PATH_DELIMITER = '/';

    private static final String PATH_DELIMITER_STRING = String.valueOf(PATH_DELIMITER);

    private static final MultiValueMap<String, String> EMPTY_QUERY_PARAMS =
            CollectionUtils.unmodifiableMultiValueMap(new LinkedMultiValueMap<>());


    /**
     * Represents an empty path.
     */
    static final PathComponent NULL_PATH_COMPONENT = new PathComponent() {
        @Override
        public String getPath() {
            return "";
        }
        @Override
        public List<String> getPathSegments() {
            return Collections.emptyList();
        }
        @Override
        public PathComponent encode(BiFunction<String, Type, String> encoder) {
            return this;
        }
        @Override
        public void verify() {
        }
        @Override
        public PathComponent expand(UriTemplateVariables uriVariables, @Nullable UnaryOperator<String> encoder) {
            return this;
        }
        @Override
        public void copyToUriComponentsBuilder(UriComponentsBuilder builder) {
        }
        @Override
        public boolean equals(@Nullable Object other) {
            return (this == other);
        }
        @Override
        public int hashCode() {
            return getClass().hashCode();
        }
    };


    @Nullable
    private final String userInfo;

    @Nullable
    private final String host;

    @Nullable
    private final String port;

    private final PathComponent path;

    private final MultiValueMap<String, String> queryParams;

    private final EncodeState encodeState;

    @Nullable
    private UnaryOperator<String> variableEncoder;


    /**
     * Package-private constructor. All arguments are optional, and can be {@code null}.
     * @param scheme the scheme
     * @param userInfo the user info
     * @param host the host
     * @param port the port
     * @param path the path
     * @param query the query parameters
     * @param fragment the fragment
     * @param encoded whether the components are already encoded
     */
    HierarchicalUriComponents(@Nullable String scheme, @Nullable String fragment, @Nullable String userInfo,
                              @Nullable String host, @Nullable String port, @Nullable PathComponent path,
                              @Nullable MultiValueMap<String, String> query, boolean encoded) {

        super(scheme, fragment);

        this.userInfo = userInfo;
        this.host = host;
        this.port = port;
        this.path = path != null ? path : NULL_PATH_COMPONENT;
        this.queryParams = query != null ? CollectionUtils.unmodifiableMultiValueMap(query) : EMPTY_QUERY_PARAMS;
        this.encodeState = encoded ? EncodeState.FULLY_ENCODED : EncodeState.RAW;

        // Check for illegal characters..
        if (encoded) {
            verify();
        }
    }

    private HierarchicalUriComponents(@Nullable String scheme, @Nullable String fragment,
                                      @Nullable String userInfo, @Nullable String host, @Nullable String port,
                                      PathComponent path, MultiValueMap<String, String> queryParams,
                                      EncodeState encodeState, @Nullable UnaryOperator<String> variableEncoder) {

        super(scheme, fragment);

        this.userInfo = userInfo;
        this.host = host;
        this.port = port;
        this.path = path;
        this.queryParams = queryParams;
        this.encodeState = encodeState;
        this.variableEncoder = variableEncoder;
    }


    // Component getters

    @Override
    @Nullable
    public String getSchemeSpecificPart() {
        return null;
    }

    @Override
    @Nullable
    public String getUserInfo() {
        return this.userInfo;
    }

    @Override
    @Nullable
    public String getHost() {
        return this.host;
    }

    @Override
    public int getPort() {
        if (this.port == null) {
            return -1;
        }
        else if (this.port.contains("{")) {
            throw new IllegalStateException(
                    "The port contains a URI variable but has not been expanded yet: " + this.port);
        }
        return Integer.parseInt(this.port);
    }

    @Override
    @NonNull
    public String getPath() {
        return this.path.getPath();
    }

    @Override
    public List<String> getPathSegments() {
        return this.path.getPathSegments();
    }

    @Override
    @Nullable
    public String getQuery() {
        if (!this.queryParams.isEmpty()) {
            StringBuilder queryBuilder = new StringBuilder();
            this.queryParams.forEach((name, values) -> {
                if (CollectionUtils.isEmpty(values)) {
                    if (queryBuilder.length() != 0) {
                        queryBuilder.append('&');
                    }
                    queryBuilder.append(name);
                }
                else {
                    for (Object value : values) {
                        if (queryBuilder.length() != 0) {
                            queryBuilder.append('&');
                        }
                        queryBuilder.append(name);
                        if (value != null) {
                            queryBuilder.append('=').append(value.toString());
                        }
                    }
                }
            });
            return queryBuilder.toString();
        }
        else {
            return null;
        }
    }

    /**
     * Return the map of query parameters. Empty if no query has been set.
     */
    @Override
    public MultiValueMap<String, String> getQueryParams() {
        return this.queryParams;
    }


    // Encoding

    /**
     * Identical to {@link #encode()} but skipping over URI variable placeholders.
     * Also {@link #variableEncoder} is initialized with the given charset for
     * use later when URI variables are expanded.
     */
    HierarchicalUriComponents encodeTemplate(Charset charset) {
        if (this.encodeState.isEncoded()) {
            return this;
        }

        // Remember the charset to encode URI variables later..
        this.variableEncoder = value -> encodeUriComponent(value, charset, Type.URI);

        UriTemplateEncoder encoder = new UriTemplateEncoder(charset);
        String schemeTo = (getScheme() != null ? encoder.apply(getScheme(), Type.SCHEME) : null);
        String fragmentTo = (getFragment() != null ? encoder.apply(getFragment(), Type.FRAGMENT) : null);
        String userInfoTo = (getUserInfo() != null ? encoder.apply(getUserInfo(), Type.USER_INFO) : null);
        String hostTo = (getHost() != null ? encoder.apply(getHost(), getHostType()) : null);
        PathComponent pathTo = this.path.encode(encoder);
        MultiValueMap<String, String> queryParamsTo = encodeQueryParams(encoder);

        return new HierarchicalUriComponents(schemeTo, fragmentTo, userInfoTo,
                hostTo, this.port, pathTo, queryParamsTo, EncodeState.TEMPLATE_ENCODED, this.variableEncoder);
    }

    @Override
    public HierarchicalUriComponents encode(Charset charset) {
        if (this.encodeState.isEncoded()) {
            return this;
        }
        String scheme = getScheme();
        String fragment = getFragment();
        String schemeTo = (scheme != null ? encodeUriComponent(scheme, charset, Type.SCHEME) : null);
        String fragmentTo = (fragment != null ? encodeUriComponent(fragment, charset, Type.FRAGMENT) : null);
        String userInfoTo = (this.userInfo != null ? encodeUriComponent(this.userInfo, charset, Type.USER_INFO) : null);
        String hostTo = (this.host != null ? encodeUriComponent(this.host, charset, getHostType()) : null);
        BiFunction<String, Type, String> encoder = (s, type) -> encodeUriComponent(s, charset, type);
        PathComponent pathTo = this.path.encode(encoder);
        MultiValueMap<String, String> queryParamsTo = encodeQueryParams(encoder);

        return new HierarchicalUriComponents(schemeTo, fragmentTo, userInfoTo,
                hostTo, this.port, pathTo, queryParamsTo, EncodeState.FULLY_ENCODED, null);
    }

    private MultiValueMap<String, String> encodeQueryParams(BiFunction<String, Type, String> encoder) {
        int size = this.queryParams.size();
        MultiValueMap<String, String> result = new LinkedMultiValueMap<>(size);
        this.queryParams.forEach((key, values) -> {
            String name = encoder.apply(key, Type.QUERY_PARAM);
            List<String> encodedValues = new ArrayList<>(values.size());
            for (String value : values) {
                encodedValues.add(value != null ? encoder.apply(value, Type.QUERY_PARAM) : null);
            }
            result.put(name, encodedValues);
        });
        return CollectionUtils.unmodifiableMultiValueMap(result);
    }

    /**
     * Encode the given source into an encoded String using the rules specified
     * by the given component and with the given options.
     * @param source the source String
     * @param encoding the encoding of the source String
     * @param type the URI component for the source
     * @return the encoded URI
     * @throws IllegalArgumentException when the given value is not a valid URI component
     */
    static String encodeUriComponent(String source, String encoding, Type type) {
        return encodeUriComponent(source, Charset.forName(encoding), type);
    }

    /**
     * Encode the given source into an encoded String using the rules specified
     * by the given component and with the given options.
     * @param source the source String
     * @param charset the encoding of the source String
     * @param type the URI component for the source
     * @return the encoded URI
     * @throws IllegalArgumentException when the given value is not a valid URI component
     */
    static String encodeUriComponent(String source, Charset charset, Type type) {
        if (!StringUtils.hasLength(source)) {
            return source;
        }
        Assert.notNull(charset, "Charset must not be null");
        Assert.notNull(type, "Type must not be null");

        byte[] bytes = source.getBytes(charset);
        boolean original = true;
        for (byte b : bytes) {
            if (!type.isAllowed(b)) {
                original = false;
                break;
            }
        }
        if (original) {
            return source;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream(bytes.length);
        for (byte b : bytes) {
            if (type.isAllowed(b)) {
                baos.write(b);
            }
            else {
                baos.write('%');
                char hex1 = Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, 16));
                char hex2 = Character.toUpperCase(Character.forDigit(b & 0xF, 16));
                baos.write(hex1);
                baos.write(hex2);
            }
        }
        return StreamUtils.copyToString(baos, charset);
    }

    private Type getHostType() {
        return (this.host != null && this.host.startsWith("[") ? Type.HOST_IPV6 : Type.HOST_IPV4);
    }

    // Verifying

    /**
     * Check if any of the URI components contain any illegal characters.
     * @throws IllegalArgumentException if any component has illegal characters
     */
    private void verify() {
        verifyUriComponent(getScheme(), Type.SCHEME);
        verifyUriComponent(this.userInfo, Type.USER_INFO);
        verifyUriComponent(this.host, getHostType());
        this.path.verify();
        this.queryParams.forEach((key, values) -> {
            verifyUriComponent(key, Type.QUERY_PARAM);
            for (String value : values) {
                verifyUriComponent(value, Type.QUERY_PARAM);
            }
        });
        verifyUriComponent(getFragment(), Type.FRAGMENT);
    }

    private static void verifyUriComponent(@Nullable String source, Type type) {
        if (source == null) {
            return;
        }
        int length = source.length();
        for (int i = 0; i < length; i++) {
            char ch = source.charAt(i);
            if (ch == '%') {
                if ((i + 2) < length) {
                    char hex1 = source.charAt(i + 1);
                    char hex2 = source.charAt(i + 2);
                    int u = Character.digit(hex1, 16);
                    int l = Character.digit(hex2, 16);
                    if (u == -1 || l == -1) {
                        throw new IllegalArgumentException("Invalid encoded sequence \"" +
                                source.substring(i) + "\"");
                    }
                    i += 2;
                }
                else {
                    throw new IllegalArgumentException("Invalid encoded sequence \"" +
                            source.substring(i) + "\"");
                }
            }
            else if (!type.isAllowed(ch)) {
                throw new IllegalArgumentException("Invalid character '" + ch + "' for " +
                        type.name() + " in \"" + source + "\"");
            }
        }
    }


    // Expanding

    @Override
    protected HierarchicalUriComponents expandInternal(UriTemplateVariables uriVariables) {
        Assert.state(!this.encodeState.equals(EncodeState.FULLY_ENCODED),
                "URI components already encoded, and could not possibly contain '{' or '}'.");

        // Array-based vars rely on the order below...
        String schemeTo = expandUriComponent(getScheme(), uriVariables, this.variableEncoder);
        String userInfoTo = expandUriComponent(this.userInfo, uriVariables, this.variableEncoder);
        String hostTo = expandUriComponent(this.host, uriVariables, this.variableEncoder);
        String portTo = expandUriComponent(this.port, uriVariables, this.variableEncoder);
        PathComponent pathTo = this.path.expand(uriVariables, this.variableEncoder);
        MultiValueMap<String, String> queryParamsTo = expandQueryParams(uriVariables);
        String fragmentTo = expandUriComponent(getFragment(), uriVariables, this.variableEncoder);

        return new HierarchicalUriComponents(schemeTo, fragmentTo, userInfoTo,
                hostTo, portTo, pathTo, queryParamsTo, this.encodeState, this.variableEncoder);
    }

    private MultiValueMap<String, String> expandQueryParams(UriTemplateVariables variables) {
        int size = this.queryParams.size();
        MultiValueMap<String, String> result = new LinkedMultiValueMap<>(size);
        UriTemplateVariables queryVariables = new QueryUriTemplateVariables(variables);
        this.queryParams.forEach((key, values) -> {
            String name = expandUriComponent(key, queryVariables, this.variableEncoder);
            List<String> expandedValues = new ArrayList<>(values.size());
            for (String value : values) {
                expandedValues.add(expandUriComponent(value, queryVariables, this.variableEncoder));
            }
            result.put(name, expandedValues);
        });
        return CollectionUtils.unmodifiableMultiValueMap(result);
    }

    @Override
    public UriComponents normalize() {
        String normalizedPath = StringUtils.cleanPath(getPath());
        FullPathComponent path = new FullPathComponent(normalizedPath);
        return new HierarchicalUriComponents(getScheme(), getFragment(), this.userInfo, this.host, this.port,
                path, this.queryParams, this.encodeState, this.variableEncoder);
    }


    // Other functionality

    @Override
    public String toUriString() {
        StringBuilder uriBuilder = new StringBuilder();
        if (getScheme() != null) {
            uriBuilder.append(getScheme()).append(':');
        }
        if (this.userInfo != null || this.host != null) {
            uriBuilder.append("//");
            if (this.userInfo != null) {
                uriBuilder.append(this.userInfo).append('@');
            }
            if (this.host != null) {
                uriBuilder.append(this.host);
            }
            if (getPort() != -1) {
                uriBuilder.append(':').append(this.port);
            }
        }
        String path = getPath();
        if (StringUtils.hasLength(path)) {
            if (uriBuilder.length() != 0 && path.charAt(0) != PATH_DELIMITER) {
                uriBuilder.append(PATH_DELIMITER);
            }
            uriBuilder.append(path);
        }
        String query = getQuery();
        if (query != null) {
            uriBuilder.append('?').append(query);
        }
        if (getFragment() != null) {
            uriBuilder.append('#').append(getFragment());
        }
        return uriBuilder.toString();
    }

    @Override
    public URI toUri() {
        try {
            if (this.encodeState.isEncoded()) {
                return new URI(toUriString());
            }
            else {
                String path = getPath();
                if (StringUtils.hasLength(path) && path.charAt(0) != PATH_DELIMITER) {
                    // Only prefix the path delimiter if something exists before it
                    if (getScheme() != null || getUserInfo() != null || getHost() != null || getPort() != -1) {
                        path = PATH_DELIMITER + path;
                    }
                }

                System.out.println("schema: " + getScheme());
                System.out.println("userInfo: " + getUserInfo());
                System.out.println("host: " + getHost());
                System.out.println("port: " + getPort());
                System.out.println("path: " + path);
                System.out.println("query: " + getQuery());
                System.out.println("fragment: " + getFragment());

                String clearSchema = getScheme();
                if(clearSchema.contains("://")){
                    clearSchema=  clearSchema.replace("://","");
                }

                URI test=  new URI(clearSchema, getUserInfo(), getHost(), getPort(), path, getQuery(), getFragment());
                String result = toString(clearSchema,null,null, getUserInfo(), getHost(), getPort(), path, getQuery(), getFragment());

                System.out.println("result: " + result);
                return test;
            }
        }
        catch (URISyntaxException ex) {
            throw new IllegalStateException("Could not create URI object: " + ex.getMessage(), ex);
        }
    }

    private String toString(String scheme,
                            String opaquePart,
                            String authority,
                            String userInfo,
                            String host,
                            int port,
                            String path,
                            String query,
                            String fragment)
    {
        StringBuffer sb = new StringBuffer();
        if (scheme != null) {
            sb.append(scheme);
            sb.append(':');
        }
        appendSchemeSpecificPart(sb, opaquePart,
                authority, userInfo, host, port,
                path, query);
        appendFragment(sb, fragment);
        return sb.toString();
    }

    private static boolean match(char c, long lowMask, long highMask) {
        if (c == 0) // 0 doesn't have a slot in the mask. So, it never matches.
            return false;
        if (c < 64)
            return ((1L << c) & lowMask) != 0;
        if (c < 128)
            return ((1L << (c - 64)) & highMask) != 0;
        return false;
    }

    private static String quote(String s, long lowMask, long highMask) {
        int n = s.length();
        StringBuffer sb = null;
        boolean allowNonASCII = ((lowMask & L_ESCAPED) != 0);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '\u0080') {
                if (!match(c, lowMask, highMask)) {
                    if (sb == null) {
                        sb = new StringBuffer();
                        sb.append(s.substring(0, i));
                    }
                    appendEscape(sb, (byte)c);
                } else {
                    if (sb != null)
                        sb.append(c);
                }
            } else if (allowNonASCII
                    && (Character.isSpaceChar(c)
                    || Character.isISOControl(c))) {
                if (sb == null) {
                    sb = new StringBuffer();
                    sb.append(s.substring(0, i));
                }
                appendEncoded(sb, c);
            } else {
                if (sb != null)
                    sb.append(c);
            }
        }
        return (sb == null) ? s : sb.toString();
    }

    private static void appendEscape(StringBuffer sb, byte b) {
        sb.append('%');
        sb.append(hexDigits[(b >> 4) & 0x0f]);
        sb.append(hexDigits[(b >> 0) & 0x0f]);
    }

    private final static char[] hexDigits = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    private static void appendEncoded(StringBuffer sb, char c) {
        ByteBuffer bb = null;
        try {
            bb = ThreadLocalCoders.encoderFor("UTF-8")
                    .encode(CharBuffer.wrap("" + c));
        } catch (CharacterCodingException x) {
            assert false;
        }
        while (bb.hasRemaining()) {
            int b = bb.get() & 0xff;
            if (b >= 0x80)
                appendEscape(sb, (byte)b);
            else
                sb.append((char)b);
        }
    }

    // Compute the low-order mask for the characters in the given string
    private static long lowMask(String chars) {
        int n = chars.length();
        long m = 0;
        for (int i = 0; i < n; i++) {
            char c = chars.charAt(i);
            if (c < 64)
                m |= (1L << c);
        }
        return m;
    }

    // Compute the high-order mask for the characters in the given string
    private static long highMask(String chars) {
        int n = chars.length();
        long m = 0;
        for (int i = 0; i < n; i++) {
            char c = chars.charAt(i);
            if ((c >= 64) && (c < 128))
                m |= (1L << (c - 64));
        }
        return m;
    }

    // Compute a low-order mask for the characters
    // between first and last, inclusive
    private static long lowMask(char first, char last) {
        long m = 0;
        int f = Math.max(Math.min(first, 63), 0);
        int l = Math.max(Math.min(last, 63), 0);
        for (int i = f; i <= l; i++)
            m |= 1L << i;
        return m;
    }

    // Compute a high-order mask for the characters
    // between first and last, inclusive
    private static long highMask(char first, char last) {
        long m = 0;
        int f = Math.max(Math.min(first, 127), 64) - 64;
        int l = Math.max(Math.min(last, 127), 64) - 64;
        for (int i = f; i <= l; i++)
            m |= 1L << i;
        return m;
    }

    // digit    = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" |
    //            "8" | "9"
    private static final long L_DIGIT = lowMask('0', '9');
    private static final long H_DIGIT = 0L;

    // upalpha  = "A" | "B" | "C" | "D" | "E" | "F" | "G" | "H" | "I" |
    //            "J" | "K" | "L" | "M" | "N" | "O" | "P" | "Q" | "R" |
    //            "S" | "T" | "U" | "V" | "W" | "X" | "Y" | "Z"
    private static final long L_UPALPHA = 0L;
    private static final long H_UPALPHA = highMask('A', 'Z');

    // lowalpha = "a" | "b" | "c" | "d" | "e" | "f" | "g" | "h" | "i" |
    //            "j" | "k" | "l" | "m" | "n" | "o" | "p" | "q" | "r" |
    //            "s" | "t" | "u" | "v" | "w" | "x" | "y" | "z"
    private static final long L_LOWALPHA = 0L;
    private static final long H_LOWALPHA = highMask('a', 'z');

    // alpha         = lowalpha | upalpha
    private static final long L_ALPHA = L_LOWALPHA | L_UPALPHA;
    private static final long H_ALPHA = H_LOWALPHA | H_UPALPHA;

    // alphanum      = alpha | digit
    private static final long L_ALPHANUM = L_DIGIT | L_ALPHA;
    private static final long H_ALPHANUM = H_DIGIT | H_ALPHA;

    // mark          = "-" | "_" | "." | "!" | "~" | "*" | "'" |
    //                 "(" | ")"
    private static final long L_MARK = lowMask("-_.!~*'()");
    private static final long H_MARK = highMask("-_.!~*'()");

    // unreserved    = alphanum | mark
    private static final long L_UNRESERVED = L_ALPHANUM | L_MARK;
    private static final long H_UNRESERVED = H_ALPHANUM | H_MARK;

    // reserved      = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
    //                 "$" | "," | "[" | "]"
    // Added per RFC2732: "[", "]"
    private static final long L_RESERVED = lowMask(";/?:@&=+$,[]");
    private static final long H_RESERVED = highMask(";/?:@&=+$,[]");

    // The zero'th bit is used to indicate that escape pairs and non-US-ASCII
    // characters are allowed; this is handled by the scanEscape method below.
    private static final long L_ESCAPED = 1L;
    private static final long H_ESCAPED = 0L;

    private static final long L_PCHAR
            = L_UNRESERVED | L_ESCAPED | lowMask(":@&=+$,");
    private static final long H_PCHAR
            = H_UNRESERVED | H_ESCAPED | highMask(":@&=+$,");

    // All valid path characters
    private static final long L_PATH = L_PCHAR | lowMask(";/");
    private static final long H_PATH = H_PCHAR | highMask(";/");

    // uric          = reserved | unreserved | escaped
    private static final long L_URIC = L_RESERVED | L_UNRESERVED | L_ESCAPED;
    private static final long H_URIC = H_RESERVED | H_UNRESERVED | H_ESCAPED;

    private void appendFragment(StringBuffer sb, String fragment) {
        if (fragment != null) {
            sb.append('#');
            sb.append(quote(fragment, L_URIC, H_URIC));
        }
    }

    private void appendSchemeSpecificPart(StringBuffer sb,
                                          String opaquePart,
                                          String authority,
                                          String userInfo,
                                          String host,
                                          int port,
                                          String path,
                                          String query)
    {
        if (opaquePart != null) {
            /* check if SSP begins with an IPv6 address
             * because we must not quote a literal IPv6 address
             */
            if (opaquePart.startsWith("//[")) {
                int end =  opaquePart.indexOf("]");
                if (end != -1 && opaquePart.indexOf(":")!=-1) {
                    String doquote, dontquote;
                    if (end == opaquePart.length()) {
                        dontquote = opaquePart;
                        doquote = "";
                    } else {
                        dontquote = opaquePart.substring(0,end+1);
                        doquote = opaquePart.substring(end+1);
                    }
                    sb.append (dontquote);
                    sb.append(quote(doquote, L_URIC, H_URIC));
                }
            } else {
                sb.append(quote(opaquePart, L_URIC, H_URIC));
            }
        } else {
            appendAuthority(sb, authority, userInfo, host, port);
            if (path != null)
                sb.append(quote(path, L_PATH, H_PATH));
            if (query != null) {
                sb.append('?');
                sb.append(quote(query, L_URIC, H_URIC));
            }
        }
    }

    private void appendAuthority(StringBuffer sb,
                                 String authority,
                                 String userInfo,
                                 String host,
                                 int port)
    {
        if (host != null) {
            sb.append("//");
            if (userInfo != null) {
                sb.append(quote(userInfo, L_USERINFO, H_USERINFO));
                sb.append('@');
            }
            boolean needBrackets = ((host.indexOf(':') >= 0)
                    && !host.startsWith("[")
                    && !host.endsWith("]"));
            if (needBrackets) sb.append('[');
            sb.append(host);
            if (needBrackets) sb.append(']');
            if (port != -1) {
                sb.append(':');
                sb.append(port);
            }
        } else if (authority != null) {
            sb.append("//");
            if (authority.startsWith("[")) {
                // authority should (but may not) contain an embedded IPv6 address
                int end = authority.indexOf("]");
                String doquote = authority, dontquote = "";
                if (end != -1 && authority.indexOf(":") != -1) {
                    // the authority contains an IPv6 address
                    if (end == authority.length()) {
                        dontquote = authority;
                        doquote = "";
                    } else {
                        dontquote = authority.substring(0 , end + 1);
                        doquote = authority.substring(end + 1);
                    }
                }
                sb.append(dontquote);
                sb.append(quote(doquote,
                        L_REG_NAME | L_SERVER,
                        H_REG_NAME | H_SERVER));
            } else {
                sb.append(quote(authority,
                        L_REG_NAME | L_SERVER,
                        H_REG_NAME | H_SERVER));
            }
        }
    }

    // userinfo      = *( unreserved | escaped |
    //                    ";" | ":" | "&" | "=" | "+" | "$" | "," )
    private static final long L_USERINFO
            = L_UNRESERVED | L_ESCAPED | lowMask(";:&=+$,");
    private static final long H_USERINFO
            = H_UNRESERVED | H_ESCAPED | highMask(";:&=+$,");

    // Dash, for use in domainlabel and toplabel
    private static final long L_DASH = lowMask("-");
    private static final long H_DASH = highMask("-");

    // reg_name      = 1*( unreserved | escaped | "$" | "," |
    //                     ";" | ":" | "@" | "&" | "=" | "+" )
    private static final long L_REG_NAME
            = L_UNRESERVED | L_ESCAPED | lowMask("$,;:@&=+");
    private static final long H_REG_NAME
            = H_UNRESERVED | H_ESCAPED | highMask("$,;:@&=+");

    // All valid characters for server-based authorities
    private static final long L_SERVER
            = L_USERINFO | L_ALPHANUM | L_DASH | lowMask(".:@[]");
    private static final long H_SERVER
            = H_USERINFO | H_ALPHANUM | H_DASH | highMask(".:@[]");


    @Override
    protected void copyToUriComponentsBuilder(UriComponentsBuilder builder) {
        if (getScheme() != null) {
            builder.scheme(getScheme());
        }
        if (getUserInfo() != null) {
            builder.userInfo(getUserInfo());
        }
        if (getHost() != null) {
            builder.host(getHost());
        }
        // Avoid parsing the port, may have URI variable..
        if (this.port != null) {
            builder.port(this.port);
        }
        this.path.copyToUriComponentsBuilder(builder);
        if (!getQueryParams().isEmpty()) {
            builder.queryParams(getQueryParams());
        }
        if (getFragment() != null) {
            builder.fragment(getFragment());
        }
    }


    @Override
    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof HierarchicalUriComponents)) {
            return false;
        }
        HierarchicalUriComponents otherComp = (HierarchicalUriComponents) other;
        return (ObjectUtils.nullSafeEquals(getScheme(), otherComp.getScheme()) &&
                ObjectUtils.nullSafeEquals(getUserInfo(), otherComp.getUserInfo()) &&
                ObjectUtils.nullSafeEquals(getHost(), otherComp.getHost()) &&
                getPort() == otherComp.getPort() &&
                this.path.equals(otherComp.path) &&
                this.queryParams.equals(otherComp.queryParams) &&
                ObjectUtils.nullSafeEquals(getFragment(), otherComp.getFragment()));
    }

    @Override
    public int hashCode() {
        int result = ObjectUtils.nullSafeHashCode(getScheme());
        result = 31 * result + ObjectUtils.nullSafeHashCode(this.userInfo);
        result = 31 * result + ObjectUtils.nullSafeHashCode(this.host);
        result = 31 * result + ObjectUtils.nullSafeHashCode(this.port);
        result = 31 * result + this.path.hashCode();
        result = 31 * result + this.queryParams.hashCode();
        result = 31 * result + ObjectUtils.nullSafeHashCode(getFragment());
        return result;
    }


    // Nested types

    /**
     * Enumeration used to identify the allowed characters per URI component.
     * <p>Contains methods to indicate whether a given character is valid in a specific URI component.
     * @see <a href="https://tools.ietf.org/html/rfc3986">RFC 3986</a>
     */
    enum Type {

        SCHEME {
            @Override
            public boolean isAllowed(int c) {
                return isAlpha(c) || isDigit(c) || '+' == c || '-' == c || '.' == c;
            }
        },
        AUTHORITY {
            @Override
            public boolean isAllowed(int c) {
                return isUnreserved(c) || isSubDelimiter(c) || ':' == c || '@' == c;
            }
        },
        USER_INFO {
            @Override
            public boolean isAllowed(int c) {
                return isUnreserved(c) || isSubDelimiter(c) || ':' == c;
            }
        },
        HOST_IPV4 {
            @Override
            public boolean isAllowed(int c) {
                return isUnreserved(c) || isSubDelimiter(c);
            }
        },
        HOST_IPV6 {
            @Override
            public boolean isAllowed(int c) {
                return isUnreserved(c) || isSubDelimiter(c) || '[' == c || ']' == c || ':' == c;
            }
        },
        PORT {
            @Override
            public boolean isAllowed(int c) {
                return isDigit(c);
            }
        },
        PATH {
            @Override
            public boolean isAllowed(int c) {
                return isPchar(c) || '/' == c;
            }
        },
        PATH_SEGMENT {
            @Override
            public boolean isAllowed(int c) {
                return isPchar(c);
            }
        },
        QUERY {
            @Override
            public boolean isAllowed(int c) {
                return isPchar(c) || '/' == c || '?' == c;
            }
        },
        QUERY_PARAM {
            @Override
            public boolean isAllowed(int c) {
                if ('=' == c || '&' == c) {
                    return false;
                }
                else {
                    return isPchar(c) || '/' == c || '?' == c;
                }
            }
        },
        FRAGMENT {
            @Override
            public boolean isAllowed(int c) {
                return isPchar(c) || '/' == c || '?' == c;
            }
        },
        URI {
            @Override
            public boolean isAllowed(int c) {
                return isUnreserved(c);
            }
        };

        /**
         * Indicates whether the given character is allowed in this URI component.
         * @return {@code true} if the character is allowed; {@code false} otherwise
         */
        public abstract boolean isAllowed(int c);

        /**
         * Indicates whether the given character is in the {@code ALPHA} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isAlpha(int c) {
            return (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z');
        }

        /**
         * Indicates whether the given character is in the {@code DIGIT} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isDigit(int c) {
            return (c >= '0' && c <= '9');
        }

        /**
         * Indicates whether the given character is in the {@code gen-delims} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isGenericDelimiter(int c) {
            return (':' == c || '/' == c || '?' == c || '#' == c || '[' == c || ']' == c || '@' == c);
        }

        /**
         * Indicates whether the given character is in the {@code sub-delims} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isSubDelimiter(int c) {
            return ('!' == c || '$' == c || '&' == c || '\'' == c || '(' == c || ')' == c || '*' == c || '+' == c ||
                    ',' == c || ';' == c || '=' == c);
        }

        /**
         * Indicates whether the given character is in the {@code reserved} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isReserved(int c) {
            return (isGenericDelimiter(c) || isSubDelimiter(c));
        }

        /**
         * Indicates whether the given character is in the {@code unreserved} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isUnreserved(int c) {
            return (isAlpha(c) || isDigit(c) || '-' == c || '.' == c || '_' == c || '~' == c);
        }

        /**
         * Indicates whether the given character is in the {@code pchar} set.
         * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC 3986, appendix A</a>
         */
        protected boolean isPchar(int c) {
            return (isUnreserved(c) || isSubDelimiter(c) || ':' == c || '@' == c);
        }
    }


    private enum EncodeState {

        /**
         * Not encoded.
         */
        RAW,

        /**
         * URI vars expanded first and then each URI component encoded by
         * quoting only illegal characters within that URI component.
         */
        FULLY_ENCODED,

        /**
         * URI template encoded first by quoting illegal characters only, and
         * then URI vars encoded more strictly when expanded, by quoting both
         * illegal chars and chars with reserved meaning.
         */
        TEMPLATE_ENCODED;


        public boolean isEncoded() {
            return this.equals(FULLY_ENCODED) || this.equals(TEMPLATE_ENCODED);
        }
    }


    private static class UriTemplateEncoder	implements BiFunction<String, Type, String> {

        private final Charset charset;

        private final StringBuilder currentLiteral = new StringBuilder();

        private final StringBuilder currentVariable = new StringBuilder();

        private final StringBuilder output = new StringBuilder();


        public UriTemplateEncoder(Charset charset) {
            this.charset = charset;
        }


        @Override
        public String apply(String source, Type type) {

            // Only URI variable (nothing to encode)..
            if (source.length() > 1 && source.charAt(0) == '{' && source.charAt(source.length() -1) == '}') {
                return source;
            }

            // Only literal (encode full source)..
            if (source.indexOf('{') == -1) {
                return encodeUriComponent(source, this.charset, type);
            }

            // Mixed literal parts and URI variables, maybe (encode literal parts only)..
            int level = 0;
            clear(this.currentLiteral);
            clear(this.currentVariable);
            clear(this.output);
            for (char c : source.toCharArray()) {
                if (c == '{') {
                    level++;
                    if (level == 1) {
                        encodeAndAppendCurrentLiteral(type);
                    }
                }
                if (c == '}' && level > 0) {
                    level--;
                    this.currentVariable.append('}');
                    if (level == 0) {
                        this.output.append(this.currentVariable);
                        clear(this.currentVariable);
                    }
                }
                else if (level > 0) {
                    this.currentVariable.append(c);
                }
                else {
                    this.currentLiteral.append(c);
                }
            }
            if (level > 0) {
                this.currentLiteral.append(this.currentVariable);
            }
            encodeAndAppendCurrentLiteral(type);
            return this.output.toString();
        }

        private void encodeAndAppendCurrentLiteral(Type type) {
            this.output.append(encodeUriComponent(this.currentLiteral.toString(), this.charset, type));
            clear(this.currentLiteral);
        }

        private void clear(StringBuilder sb) {
            sb.delete(0, sb.length());
        }
    }


    /**
     * Defines the contract for path (segments).
     */
    interface PathComponent extends Serializable {

        String getPath();

        List<String> getPathSegments();

        PathComponent encode(BiFunction<String, Type, String> encoder);

        void verify();

        PathComponent expand(UriTemplateVariables uriVariables, @Nullable UnaryOperator<String> encoder);

        void copyToUriComponentsBuilder(UriComponentsBuilder builder);
    }


    /**
     * Represents a path backed by a String.
     */
    static final class FullPathComponent implements PathComponent {

        private final String path;

        public FullPathComponent(@Nullable String path) {
            this.path = (path != null ? path : "");
        }

        @Override
        public String getPath() {
            return this.path;
        }

        @Override
        public List<String> getPathSegments() {
            String[] segments = StringUtils.tokenizeToStringArray(getPath(), PATH_DELIMITER_STRING);
            return Collections.unmodifiableList(Arrays.asList(segments));
        }

        @Override
        public PathComponent encode(BiFunction<String, Type, String> encoder) {
            String encodedPath = encoder.apply(getPath(), Type.PATH);
            return new FullPathComponent(encodedPath);
        }

        @Override
        public void verify() {
            verifyUriComponent(getPath(), Type.PATH);
        }

        @Override
        public PathComponent expand(UriTemplateVariables uriVariables, @Nullable UnaryOperator<String> encoder) {
            String expandedPath = expandUriComponent(getPath(), uriVariables, encoder);
            return new FullPathComponent(expandedPath);
        }

        @Override
        public void copyToUriComponentsBuilder(UriComponentsBuilder builder) {
            builder.path(getPath());
        }

        @Override
        public boolean equals(@Nullable Object other) {
            return (this == other || (other instanceof FullPathComponent &&
                    getPath().equals(((FullPathComponent) other).getPath())));
        }

        @Override
        public int hashCode() {
            return getPath().hashCode();
        }
    }


    /**
     * Represents a path backed by a String list (i.e. path segments).
     */
    static final class PathSegmentComponent implements PathComponent {

        private final List<String> pathSegments;

        public PathSegmentComponent(List<String> pathSegments) {
            Assert.notNull(pathSegments, "List must not be null");
            this.pathSegments = Collections.unmodifiableList(new ArrayList<>(pathSegments));
        }

        @Override
        public String getPath() {
            String delimiter = PATH_DELIMITER_STRING;
            StringJoiner pathBuilder = new StringJoiner(delimiter, delimiter, "");
            for (String pathSegment : this.pathSegments) {
                pathBuilder.add(pathSegment);
            }
            return pathBuilder.toString();
        }

        @Override
        public List<String> getPathSegments() {
            return this.pathSegments;
        }

        @Override
        public PathComponent encode(BiFunction<String, Type, String> encoder) {
            List<String> pathSegments = getPathSegments();
            List<String> encodedPathSegments = new ArrayList<>(pathSegments.size());
            for (String pathSegment : pathSegments) {
                String encodedPathSegment = encoder.apply(pathSegment, Type.PATH_SEGMENT);
                encodedPathSegments.add(encodedPathSegment);
            }
            return new PathSegmentComponent(encodedPathSegments);
        }

        @Override
        public void verify() {
            for (String pathSegment : getPathSegments()) {
                verifyUriComponent(pathSegment, Type.PATH_SEGMENT);
            }
        }

        @Override
        public PathComponent expand(UriTemplateVariables uriVariables, @Nullable UnaryOperator<String> encoder) {
            List<String> pathSegments = getPathSegments();
            List<String> expandedPathSegments = new ArrayList<>(pathSegments.size());
            for (String pathSegment : pathSegments) {
                String expandedPathSegment = expandUriComponent(pathSegment, uriVariables, encoder);
                expandedPathSegments.add(expandedPathSegment);
            }
            return new PathSegmentComponent(expandedPathSegments);
        }

        @Override
        public void copyToUriComponentsBuilder(UriComponentsBuilder builder) {
            builder.pathSegment(StringUtils.toStringArray(getPathSegments()));
        }

        @Override
        public boolean equals(@Nullable Object other) {
            return (this == other || (other instanceof PathSegmentComponent &&
                    getPathSegments().equals(((PathSegmentComponent) other).getPathSegments())));
        }

        @Override
        public int hashCode() {
            return getPathSegments().hashCode();
        }
    }


    /**
     * Represents a collection of PathComponents.
     */
    static final class PathComponentComposite implements PathComponent {

        private final List<PathComponent> pathComponents;

        public PathComponentComposite(List<PathComponent> pathComponents) {
            Assert.notNull(pathComponents, "PathComponent List must not be null");
            this.pathComponents = pathComponents;
        }

        @Override
        public String getPath() {
            StringBuilder pathBuilder = new StringBuilder();
            for (PathComponent pathComponent : this.pathComponents) {
                pathBuilder.append(pathComponent.getPath());
            }
            return pathBuilder.toString();
        }

        @Override
        public List<String> getPathSegments() {
            List<String> result = new ArrayList<>();
            for (PathComponent pathComponent : this.pathComponents) {
                result.addAll(pathComponent.getPathSegments());
            }
            return result;
        }

        @Override
        public PathComponent encode(BiFunction<String, Type, String> encoder) {
            List<PathComponent> encodedComponents = new ArrayList<>(this.pathComponents.size());
            for (PathComponent pathComponent : this.pathComponents) {
                encodedComponents.add(pathComponent.encode(encoder));
            }
            return new PathComponentComposite(encodedComponents);
        }

        @Override
        public void verify() {
            for (PathComponent pathComponent : this.pathComponents) {
                pathComponent.verify();
            }
        }

        @Override
        public PathComponent expand(UriTemplateVariables uriVariables, @Nullable UnaryOperator<String> encoder) {
            List<PathComponent> expandedComponents = new ArrayList<>(this.pathComponents.size());
            for (PathComponent pathComponent : this.pathComponents) {
                expandedComponents.add(pathComponent.expand(uriVariables, encoder));
            }
            return new PathComponentComposite(expandedComponents);
        }

        @Override
        public void copyToUriComponentsBuilder(UriComponentsBuilder builder) {
            for (PathComponent pathComponent : this.pathComponents) {
                pathComponent.copyToUriComponentsBuilder(builder);
            }
        }
    }


    private static class QueryUriTemplateVariables implements UriTemplateVariables {

        private final UriTemplateVariables delegate;

        public QueryUriTemplateVariables(UriTemplateVariables delegate) {
            this.delegate = delegate;
        }

        @Override
        public Object getValue(@Nullable String name) {
            Object value = this.delegate.getValue(name);
            if (ObjectUtils.isArray(value)) {
                value = StringUtils.arrayToCommaDelimitedString(ObjectUtils.toObjectArray(value));
            }
            return value;
        }
    }

}
