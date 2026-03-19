package com.snc.discovery;

import java.util.Map;

interface AkeylessHttpTransport {
    Map<String, Object> postJson(String url, Object payload) throws Exception;
}

