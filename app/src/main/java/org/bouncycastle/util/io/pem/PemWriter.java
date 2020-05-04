package org.bouncycastle.util.io.pem;

import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Iterator;

/**
 * A generic PEM writer, based on RFC 1421
 */
public class PemWriter
        extends BufferedWriter {
    private static final int LINE_LENGTH = 64;

    private final int nlLength;
    private char[] buf = new char[LINE_LENGTH];

    /**
     * Base constructor.
     *
     * @param out output stream to use.
     */
    public PemWriter(Writer out) {
        super(out);

        String nl = Strings.lineSeparator();
        if (nl != null) {
            nlLength = nl.length();
        } else {
            nlLength = 2;
        }
    }

    public void writeObject(PemObjectGenerator objGen)
            throws IOException {
        PemObject obj = objGen.generate();

        writePreEncapsulationBoundary(obj.getType());

        if (!obj.getHeaders().isEmpty()) {
            for (Iterator it = obj.getHeaders().iterator(); it.hasNext(); ) {
                PemHeader hdr = (PemHeader) it.next();

                this.write(hdr.getName());
                this.write(": ");
                this.write(hdr.getValue());
                this.newLine();
            }

            this.newLine();
        }

        writeEncoded(obj.getContent());
        writePostEncapsulationBoundary(obj.getType());
    }

    private void writeEncoded(byte[] bytes)
            throws IOException {
        bytes = Base64.encode(bytes);

        for (int i = 0; i < bytes.length; i += buf.length) {
            int index = 0;

            while (index != buf.length) {
                if ((i + index) >= bytes.length) {
                    break;
                }
                buf[index] = (char) bytes[i + index];
                index++;
            }
            this.write(buf, 0, index);
            this.newLine();
        }
    }

    private void writePreEncapsulationBoundary(
            String type)
            throws IOException {
        this.write("-----BEGIN " + type + "-----");
        this.newLine();
    }

    private void writePostEncapsulationBoundary(
            String type)
            throws IOException {
        this.write("-----END " + type + "-----");
        this.newLine();
    }
}
