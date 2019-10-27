package com.jwolfe.ankyl.crypto;

public abstract class CryptoBoxBase implements CryptoBox {
    String algorithm;

    String mode;

    String padding;

    @Override
    public String getMode() {
        return mode;
    }

    @Override
    public void setMode(String mode) {
        this.mode = mode;
    }

    @Override
    public String getPadding() {
        return padding;
    }

    @Override
    public void setPadding(String padding) {
        this.padding = padding;
    }

    @Override
    public String getTransformation() {
        return algorithm + "/" + mode + "/" + padding;
    }
}
