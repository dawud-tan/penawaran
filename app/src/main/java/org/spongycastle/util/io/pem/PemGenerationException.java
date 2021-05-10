package org.spongycastle.util.io.pem;

import java.io.IOException;

/**
 * Exception thrown on failure to generate a PEM object.
 */
public class PemGenerationException
    extends IOException
{
    private Throwable cause;


    public Throwable getCause()
    {
        return cause;
    }
}
