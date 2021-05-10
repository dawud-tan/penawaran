package org.spongycastle.cms;

public class CMSRuntimeException
        extends RuntimeException {
    Exception e;

    public CMSRuntimeException(
            String name) {
        super(name);
    }


    public Throwable getCause() {
        return e;
    }
}
