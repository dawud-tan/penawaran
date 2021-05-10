package org.spongycastle.mail.smime;

public class SMIMEException
        extends Exception {
    Exception e;


    public SMIMEException(
            String name,
            Exception e) {
        super(name);

        this.e = e;
    }

    public Throwable getCause() {
        return e;
    }
}