package org.spongycastle.i18n;

import java.util.Locale;

public class MissingEntryException extends RuntimeException {

    protected final String resource;
    protected final String key;
    protected final ClassLoader loader;
    protected final Locale locale;

    private String debugMsg;

    public MissingEntryException(String message, String resource, String key, Locale locale, ClassLoader loader) {
        super(message);
        this.resource = resource;
        this.key = key;
        this.locale = locale;
        this.loader = loader;
    }


}
