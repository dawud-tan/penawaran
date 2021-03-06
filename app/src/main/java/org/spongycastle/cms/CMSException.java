package org.spongycastle.cms;

public class CMSException
        extends Exception {
    Exception e;

    public CMSException(
            String msg) {
        super(msg);
    }

    public CMSException(
            String msg,
            Exception e) {
        super(msg);

        this.e = e;
    }


    public Throwable getCause() {
        return e;
    }
}
