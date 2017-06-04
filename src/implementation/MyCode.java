/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import x509.v3.GuiV3;

/**
 *
 * @author j
 */
public class MyCode extends x509.v3.CodeV3 {
	
	private KeyStore ks;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("pkcs12");
			ks.load(null, null);
			
			FileOutputStream fs = new FileOutputStream("keystore.p12", true);
			
			ks.store(fs, "pass".toCharArray());
			
			fs.close();
			
			this.ks = ks;
			
            return ks.aliases();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }   catch (IOException ex) {
			Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		} catch (CertificateException ex) {
			Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}
    }

    @Override
    public void resetLocalKeystore() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int loadKeypair(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean saveKeypair(String string) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.access.getPublicKeyAlgorithm());
			KeyPair kp = kpg.genKeyPair();
			
			X509Certificate cert = new X509CertImpl();
			
			//this.ks.setKeyEntry(string, kp.getPublic(), "secret".toCharArray(), certs);
			
			return true;
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
			return false;
		}
    }

    @Override
    public boolean removeKeypair(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean signCertificate(String string, String string1) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean importCertificate(File file, String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuer(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getRSAKeyLength(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<String> getIssuers(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean generateCSR(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
