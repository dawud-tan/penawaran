package org.spongycastle.mail.smime;

import java.io.IOException;
import java.io.OutputStream;

public interface SMIMEStreamingProcessor {
    void write(OutputStream out)
            throws IOException;
}