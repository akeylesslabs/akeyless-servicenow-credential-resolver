package com.snc.discovery;

class MidPropertySource {

    String getProperty(String name, String dflt) {
        try {
            Class<?> c = Class.forName("com.service_now.mid.services.Config");
            Object cfg = c.getMethod("get").invoke(null);
            String v = (String) c.getMethod("getProperty", String.class).invoke(cfg, name);
            if (v == null) {
                v = (String) c.getMethod("getProperty", String.class).invoke(cfg, "mid.property." + name);
            }
            return v != null ? v : dflt;
        } catch (Throwable t) {
            String v = System.getProperty(name);
            if (v == null) {
                v = System.getenv(name.replace('.', '_').toUpperCase());
            }
            return v != null ? v : dflt;
        }
    }

    String envOr(String name, String dflt) {
        String v = System.getProperty(name);
        if (v == null || v.isEmpty()) {
            v = System.getenv(name);
        }
        return v == null || v.isEmpty() ? dflt : v;
    }
}

