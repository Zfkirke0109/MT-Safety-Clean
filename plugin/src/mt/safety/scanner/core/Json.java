package mt.safety.scanner.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Minimal, dependency-free JSON parser.
 *
 * <p>MT plugins run inside MT Manager, where {@code org.json} is available, but this core is kept
 * free of Android classes so the whole detection engine can be compiled and tested on a desktop
 * JVM. Hence a small parser of our own.
 *
 * <p>Parsing is deliberately strict about structure but lenient about trailing content, because the
 * input is an untrusted {@code manifest.json} from a package we are about to judge. Any malformed
 * input raises {@link JsonException} rather than producing a half-parsed tree.
 */
public final class Json {

    /** Thrown when input is not well-formed JSON. */
    public static class JsonException extends Exception {
        private static final long serialVersionUID = 1L;

        public JsonException(String message) {
            super(message);
        }
    }

    private final String src;
    private int pos;
    /** Guards against deeply nested input built to exhaust the stack. */
    private int depth;

    private static final int MAX_DEPTH = 64;

    /**
     * JSON's number grammar.
     *
     * <p>The scanning loop below is deliberately loose about which characters it gathers, so the token
     * it produces is checked against the real grammar rather than handed straight to
     * {@link Double#valueOf}, which accepts plenty that JSON does not ({@code +1}, {@code 1d},
     * {@code Infinity}). Being more permissive than the parser MT Manager uses would leave somewhere
     * for a manifest to mean two different things.
     */
    private static final Pattern NUMBER = Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][-+]?[0-9]+)?");

    private Json(String src) {
        this.src = src;
    }

    /** Parses {@code text} and returns a Map, List, String, Double, Boolean or null. */
    public static Object parse(String text) throws JsonException {
        if (text == null) {
            throw new JsonException("no input");
        }
        Json p = new Json(stripBom(text));
        p.skipWhitespace();
        Object value = p.readValue();
        p.skipWhitespace();
        if (p.pos < p.src.length()) {
            throw new JsonException("trailing content at offset " + p.pos);
        }
        return value;
    }

    /** Parses {@code text} expecting a JSON object at the top level. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) throws JsonException {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new JsonException("expected a JSON object at the top level");
        }
        return (Map<String, Object>) value;
    }

    private static String stripBom(String text) {
        if (text.length() > 0 && text.charAt(0) == '\ufeff') {
            return text.substring(1);
        }
        return text;
    }

    // ---------------------------------------------------------------- readers

    private Object readValue() throws JsonException {
        if (pos >= src.length()) {
            throw new JsonException("unexpected end of input");
        }
        char c = src.charAt(pos);
        switch (c) {
            case '{':
                return readObject();
            case '[':
                return readArray();
            case '"':
                return readString();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return readNumber();
        }
    }

    private Map<String, Object> readObject() throws JsonException {
        enter();
        pos++; // '{'
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            depth--;
            return map;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw new JsonException("expected a string key at offset " + pos);
            }
            String key = readString();
            skipWhitespace();
            if (peek() != ':') {
                throw new JsonException("expected ':' at offset " + pos);
            }
            pos++;
            skipWhitespace();
            map.put(key, readValue());
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                pos++;
                continue;
            }
            if (c == '}') {
                pos++;
                depth--;
                return map;
            }
            throw new JsonException("expected ',' or '}' at offset " + pos);
        }
    }

    private List<Object> readArray() throws JsonException {
        enter();
        pos++; // '['
        List<Object> list = new ArrayList<Object>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            depth--;
            return list;
        }
        while (true) {
            skipWhitespace();
            list.add(readValue());
            skipWhitespace();
            char c = peek();
            if (c == ',') {
                pos++;
                continue;
            }
            if (c == ']') {
                pos++;
                depth--;
                return list;
            }
            throw new JsonException("expected ',' or ']' at offset " + pos);
        }
    }

    private String readString() throws JsonException {
        pos++; // opening quote
        StringBuilder out = new StringBuilder();
        while (true) {
            if (pos >= src.length()) {
                throw new JsonException("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (pos >= src.length()) {
                throw new JsonException("unterminated escape");
            }
            char esc = src.charAt(pos++);
            switch (esc) {
                case '"':
                    out.append('"');
                    break;
                case '\\':
                    out.append('\\');
                    break;
                case '/':
                    out.append('/');
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (pos + 4 > src.length()) {
                        throw new JsonException("truncated \\u escape");
                    }
                    String hex = src.substring(pos, pos + 4);
                    pos += 4;
                    try {
                        out.append((char) Integer.parseInt(hex, 16));
                    } catch (NumberFormatException e) {
                        throw new JsonException("bad \\u escape: " + hex);
                    }
                    break;
                default:
                    throw new JsonException("bad escape: \\" + esc);
            }
        }
    }

    private Double readNumber() throws JsonException {
        int start = pos;
        // JSON allows a leading minus only. Accepting '+' would make this parser more permissive than
        // the one MT Manager uses, and any disagreement about an untrusted manifest is a place to hide.
        if (peek() == '-') {
            pos++;
        }
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '-' || c == '+') {
                pos++;
            } else {
                break;
            }
        }
        String text = src.substring(start, pos);
        if (text.length() == 0) {
            throw new JsonException("unexpected character '" + src.charAt(start) + "' at offset " + start);
        }
        if (!NUMBER.matcher(text).matches()) {
            throw new JsonException("bad number: " + text);
        }
        try {
            return Double.valueOf(text);
        } catch (NumberFormatException e) {
            throw new JsonException("bad number: " + text);
        }
    }

    // ---------------------------------------------------------------- helpers

    private void enter() throws JsonException {
        if (++depth > MAX_DEPTH) {
            throw new JsonException("nesting deeper than " + MAX_DEPTH + " levels");
        }
    }

    private char peek() throws JsonException {
        if (pos >= src.length()) {
            throw new JsonException("unexpected end of input");
        }
        return src.charAt(pos);
    }

    private void expect(String literal) throws JsonException {
        if (!src.startsWith(literal, pos)) {
            throw new JsonException("expected '" + literal + "' at offset " + pos);
        }
        pos += literal.length();
    }

    private void skipWhitespace() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    // ------------------------------------------------------------ accessors

    /** Returns a string field, or {@code fallback} when absent or not a scalar. */
    public static String str(Map<String, Object> obj, String key, String fallback) {
        if (obj == null) {
            return fallback;
        }
        Object v = obj.get(key);
        if (v == null) {
            return fallback;
        }
        if (v instanceof String) {
            return (String) v;
        }
        if (v instanceof Double) {
            double d = ((Double) v).doubleValue();
            if (d == Math.floor(d) && !Double.isInfinite(d)) {
                return Long.toString((long) d);
            }
            return v.toString();
        }
        if (v instanceof Boolean) {
            return v.toString();
        }
        return fallback;
    }

    /** Returns an int field, or {@code fallback} when absent or not numeric. */
    public static int integer(Map<String, Object> obj, String key, int fallback) {
        if (obj == null) {
            return fallback;
        }
        Object v = obj.get(key);
        if (v instanceof Double) {
            return (int) ((Double) v).doubleValue();
        }
        if (v instanceof String) {
            try {
                return Integer.parseInt(((String) v).trim());
            } catch (NumberFormatException ignored) {
                return fallback;
            }
        }
        return fallback;
    }

    /** Returns the string elements of an array field; never null. */
    public static List<String> stringList(Map<String, Object> obj, String key) {
        List<String> out = new ArrayList<String>();
        if (obj == null) {
            return out;
        }
        Object v = obj.get(key);
        if (!(v instanceof List)) {
            return out;
        }
        for (Object item : (List<?>) v) {
            if (item instanceof String) {
                out.add((String) item);
            }
        }
        return out;
    }

    /** Returns the object elements of an array field; never null. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> objectList(Map<String, Object> obj, String key) {
        List<Map<String, Object>> out = new ArrayList<Map<String, Object>>();
        if (obj == null) {
            return out;
        }
        Object v = obj.get(key);
        if (!(v instanceof List)) {
            return out;
        }
        for (Object item : (List<?>) v) {
            if (item instanceof Map) {
                out.add((Map<String, Object>) item);
            }
        }
        return out;
    }

    /** Escapes a string for embedding in JSON output, including the surrounding quotes. */
    public static String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }
}
