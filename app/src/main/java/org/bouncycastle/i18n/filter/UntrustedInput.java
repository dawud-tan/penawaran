
package org.bouncycastle.i18n.filter;

/**
 * Wrapper class to mark untrusted input.
 */
public class UntrustedInput {

    protected Object input;

    /**
     * Construct a new UntrustedInput instance.
     *
     * @param input the untrusted input Object
     */
    public UntrustedInput(Object input) {
        this.input = input;
    }

    /**
     * Returns the untrusted input as Object.
     *
     * @return the <code>input</code> as Object
     */
    public Object getInput() {
        return input;
    }

    public String toString() {
        return input.toString();
    }

}
