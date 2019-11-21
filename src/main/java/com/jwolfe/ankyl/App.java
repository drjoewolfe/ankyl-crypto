package com.jwolfe.ankyl;

import com.jwolfe.ankyl.client.CryptoTryoutMain;

import javax.swing.*;

public class App {
    public static void main(String[] args) {
        JFrame frame = new JFrame("Ankyl: Crypto Main");
        frame.setContentPane(new CryptoTryoutMain().cryptoMainPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setSize(1000, 800);
        frame.setVisible(true);
    }
}
