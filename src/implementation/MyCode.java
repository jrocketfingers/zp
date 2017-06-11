/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.InhibitAnyPolicyExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import x509.v3.GuiV3;

/**
 *
 * @author j
 */
public class MyCode extends x509.v3.CodeV3 {

    private static String areyoufuckingmental;
    private static KeyStore ks;
    private static final String KEY_STORE_NAME = "keystore.p12";
    private static final String KEY_STORE_PASS = "holaamigos";

    
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public final static String LINE_SEPARATOR = System.getProperty("line.separator");
    private static final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

    static {
        ks = null;
        try {
            ks = KeyStore.getInstance("pkcs12");
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        this.access.setVersion(2);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {

            File keystoreFile = new File(KEY_STORE_NAME);
            if(!keystoreFile.exists()){
                ks.load(null, null);
                FileOutputStream keystoreNewFOS = new FileOutputStream(KEY_STORE_NAME, true);

                ks.store(keystoreNewFOS, KEY_STORE_PASS.toCharArray());

                keystoreNewFOS.close();
            } else {
                FileInputStream keystoreIn = new FileInputStream(KEY_STORE_NAME);
                ks.load(keystoreIn, KEY_STORE_PASS.toCharArray());
                keystoreIn.close();
            }

            return ks.aliases();
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    @Override
    public void resetLocalKeystore() {

        FileOutputStream outfile = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            outfile = new FileOutputStream(KEY_STORE_NAME);
            ks.store(outfile, KEY_STORE_PASS.toCharArray());
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if(outfile != null) {
                try {
                    outfile.close();
                } catch (IOException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        loadLocalKeystore();
    }

    @Override
    public int loadKeypair(String string) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(string);

            areyoufuckingmental = string;

            X500Principal issuer;
            issuer = cert.getIssuerX500Principal(); // if it's self-signed

            this.access.setIssuer(issuer.getName());
            this.access.setIssuerSignatureAlgorithm(cert.getSigAlgName());

            this.access.setNotAfter(cert.getNotAfter());
            this.access.setNotBefore(cert.getNotBefore());

            X500Principal subjectPrincipal = cert.getSubjectX500Principal();
            String[] params = subjectPrincipal.toString().split(",");

            for(String param: params) {
                String[] split = param.split("=");

                if(split[0].trim().equals("CN"))
                    access.setSubjectCommonName(split[1]);
                else if(split[0].trim().equals("O"))
                    access.setSubjectOrganization(split[1]);
                else if(split[0].trim().equals("OU"))
                    access.setSubjectOrganizationUnit(split[1]);
                else if(split[0].trim().equals("L"))
                    access.setSubjectLocality(split[1]);
                else if(split[0].trim().equals("C"))
                    access.setSubjectCountry(split[1]);
                else if(split[0].trim().equals("ST"))
                    access.setSubjectState(split[1]);
            }

            this.access.setAuthorityIssuer(string);

            if(cert.getBasicConstraints() != -1)
                return 2;
            else if(ks.getCertificateChain(string).length > 1)
                return 1;
            else
                return 0;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return -1;
    }

    public X509Certificate createSignedCert(Date notBefore, Date notAfter, X500Name owner, X500Name issuer, String publicKeyAlgorithm, PublicKey subjectPublicKey, BigInteger serialNumber, String publicKeySignatureAlgorithm, PrivateKey issuerPrivateKey) {
        try {
            CertificateValidity interval;
            interval = new CertificateValidity(notBefore, notAfter);

            X509CertInfo certInfo = new X509CertInfo();
            
            certInfo.set(X509CertInfo.VALIDITY, interval);
            
            certInfo.set(X509CertInfo.SUBJECT, owner);
            certInfo.set(X509CertInfo.ISSUER, issuer); // the certificate is self-signed
            
            certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            
            certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(publicKeySignatureAlgorithm)));
            
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(subjectPublicKey));
            
            certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));

            // Setting extensions without bouncy castle is just a pure hell, handling DER encoded values and digging through internal APIs - I've at least tried
            //CertificateExtensions ext = new CertificateExtensions();
            //ext.set(InhibitAnyPolicyExtension.NAME, new InhibitAnyPolicyExtension(int(access.getInhibitAnyPolicy())));

            // Too much complexity handling ASN strucutres in Java for little gain
            //access.getAlternativeName(0);
            //GeneralNames gnames = new GeneralNames();
            //gnames.add()
            //ext.set(SubjectAlternativeNameExtension.NAME, new SubjectAlternativeNameExtension()));
            
            X509CertImpl cert = new X509CertImpl(certInfo);
            cert.sign(issuerPrivateKey, publicKeySignatureAlgorithm);
            
            return cert;
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public X509Certificate signACert(X509Certificate subjectCert, X509Certificate issuerCert, PrivateKey issuerPrivateKey, String publicKeySignatureAlgorithm) {
        try {
            X500Principal subjectPrincipal = subjectCert.getSubjectX500Principal();
            X500Principal issuerPrincipal = issuerCert.getSubjectX500Principal();  //confusing, I know
            X500Name subjectName = new X500Name(subjectPrincipal.getName());
            X500Name issuerName = new X500Name(issuerPrincipal.getName());

            X509Certificate cert = createSignedCert(subjectCert.getNotBefore(), subjectCert.getNotAfter(), subjectName, issuerName, subjectCert.getPublicKey().getAlgorithm(), subjectCert.getPublicKey(), subjectCert.getSerialNumber(), publicKeySignatureAlgorithm, issuerPrivateKey);

            return cert;
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public boolean saveKeypair(String string) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            //AlgorithmParameterSpec aps = new ECGenParameterSpec(access.getPublicKeyECCurve());
            //kpg.initialize(aps);
            KeyPair kp = kpg.genKeyPair();

            StringBuilder paramBuilder = new StringBuilder();

            if(access.getSubjectCommonName()!= null && !access.getSubjectCommonName().isEmpty())
                paramBuilder.append(String.format("CN=%s", access.getSubjectCommonName()));

            if(access.getSubjectOrganizationUnit()!= null && !access.getSubjectOrganizationUnit().isEmpty())
                paramBuilder.append(String.format(",OU=%s", access.getSubjectOrganizationUnit()));

            if(access.getSubjectOrganization()!= null && !access.getSubjectOrganization().isEmpty())
                paramBuilder.append(String.format(",O=%s", access.getSubjectOrganization()));

            if(access.getSubjectLocality()!= null && !access.getSubjectLocality().isEmpty())
                paramBuilder.append(String.format(",L=%s", access.getSubjectLocality()));

            if(access.getSubjectState()!= null && !access.getSubjectState().isEmpty())
                paramBuilder.append(String.format(",ST=%s", access.getSubjectState()));

            if(access.getSubjectCountry()!= null && !access.getSubjectCountry().isEmpty())
                paramBuilder.append(String.format(",C=%s", access.getSubjectCountry()));

            X500Name owner;
            owner = new X500Name(paramBuilder.toString());

            BigInteger serialNumber = new BigInteger(access.getSerialNumber());

            Certificate cert = this.createSignedCert(access.getNotBefore(), access.getNotAfter(), owner, owner, access.getPublicKeyAlgorithm(), kp.getPublic(), serialNumber, access.getPublicKeySignatureAlgorithm(), kp.getPrivate());

            FileOutputStream keystoreOut = new FileOutputStream(KEY_STORE_NAME);

            this.loadLocalKeystore();

            ks.setKeyEntry(string, kp.getPrivate(), KEY_STORE_PASS.toCharArray(), new Certificate[] {cert});
            ks.store(keystoreOut, KEY_STORE_PASS.toCharArray());
            keystoreOut.close();

            return true;
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public boolean removeKeypair(String string) {
        try {
            ks.deleteEntry(string);

            ks.store(new FileOutputStream(KEY_STORE_NAME), KEY_STORE_PASS.toCharArray());

            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public boolean importKeypair(String keypair_name, String filename, String password) {
        File file = new File(filename);

        if(!file.exists()) {
            return false;
        }

        try {
            FileInputStream inFile = new FileInputStream(file);
            KeyStore pkcs = KeyStore.getInstance("PKCS12");
            pkcs.load(inFile, password.toCharArray());

            Key key = pkcs.getKey(keypair_name, password.toCharArray());

            Certificate cert = pkcs.getCertificate(keypair_name);

            ks.setKeyEntry(keypair_name, key, KEY_STORE_PASS.toCharArray(), new Certificate[] { cert });

            ks.store(new FileOutputStream(KEY_STORE_NAME), KEY_STORE_PASS.toCharArray());

            return true;
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public boolean exportKeypair(String string, String filename, String password) {
        FileOutputStream outfile = null;

        try {
            Key key = ks.getKey(string, KEY_STORE_PASS.toCharArray());
            Certificate[] certChain = ks.getCertificateChain(string);

            KeyStore pkcs = KeyStore.getInstance("PKCS12");

            pkcs.load(null, null);

            pkcs.setKeyEntry(string, key, password.toCharArray(), certChain);

            outfile = new FileOutputStream(filename);
            pkcs.store(outfile, password.toCharArray());

            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if(outfile != null)
                try {
                    outfile.close();
            } catch (IOException ex) {
                Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return false;
    }

    @Override
    public boolean signCertificate(String issuer, String algorithm) {
        try {
            PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuer, KEY_STORE_PASS.toCharArray());
            PrivateKey subjectPrivateKey = (PrivateKey) ks.getKey(this.areyoufuckingmental, KEY_STORE_PASS.toCharArray());
            X509Certificate subjectCert = (X509Certificate) ks.getCertificate(this.areyoufuckingmental);
            X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuer);

            ks.deleteEntry(this.areyoufuckingmental);

            X509Certificate newCert = signACert(subjectCert, issuerCert, issuerPrivateKey, algorithm);

            ks.setKeyEntry(areyoufuckingmental, subjectPrivateKey, KEY_STORE_PASS.toCharArray(), new Certificate[] {newCert, issuerCert});

            FileOutputStream outfile = new FileOutputStream(KEY_STORE_NAME);

            ks.store(outfile, KEY_STORE_PASS.toCharArray());

            outfile.close();

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public boolean importCertificate(File file, String string) {
        FileInputStream inStream = null;

        try {
            inStream = new FileInputStream(file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);

            ks.setCertificateEntry(string, cert);

            ks.store(new FileOutputStream(KEY_STORE_NAME), KEY_STORE_PASS.toCharArray());

            return true;
        } catch (CertificateException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if(inStream != null){
                try {
                    inStream.close();
                } catch (IOException ex) {
                    Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        return false;
    }

    @Override
    public boolean exportCertificate(File file, int pem) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(areyoufuckingmental);
            byte[] encoded = cert.getEncoded(); // it's der encoded, so is it really encoded?

            if(pem == 1) {
                String body = new String(encoder.encode(encoded)); // ENCODETOTHEMAX
                String complete = BEGIN_CERT + LINE_SEPARATOR + body + LINE_SEPARATOR + END_CERT + LINE_SEPARATOR;
                encoded = complete.getBytes();
            }

            FileOutputStream outfile = new FileOutputStream(file);
            outfile.write(encoded);
            outfile.close();

            return true;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public String getIssuer(String string) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(string);

            X500Principal principal = cert.getIssuerX500Principal();

            return principal.getName();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(string);

            PublicKey pub = cert.getPublicKey();

            return pub.getAlgorithm();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public int getRSAKeyLength(String string) {
        X509Certificate cert;
        try {
            cert = (X509Certificate) ks.getCertificate(string);
            PublicKey pub = cert.getPublicKey();

            String algorithm = pub.getAlgorithm();

            if(algorithm != "RSA")
                return 0;

            return ((RSAPublicKey)pub).getModulus().bitLength();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return 0;
    }

    @Override
    public List<String> getIssuers(String string) {
        try {
            Enumeration<String> aliases = ks.aliases();

            List<String> listAliases = Collections.list(aliases);
            List<String> CAs = new ArrayList<String>();

            for(String alias: listAliases) {
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

                if(cert.getBasicConstraints() != -1 && !alias.equals(string)) {
                    CAs.add(alias);
                }
            }

            return CAs;
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    @Override
    public boolean generateCSR(String string) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(string);
            PrivateKey key = (PrivateKey) ks.getKey(string, KEY_STORE_PASS.toCharArray());

            X500Principal x500Principal = cert.getSubjectX500Principal();

            final DerOutputStream der1 = new DerOutputStream();
            der1.putInteger(BigInteger.ZERO);
            der1.write(x500Principal.getEncoded());
            der1.write(cert.getPublicKey().getEncoded());
            
            // der encoded certificate request info
            DerOutputStream der2 = new DerOutputStream();
            der2.write((byte) 48, der1);

            byte[] certificateRequestInfo = der2.toByteArray();
            Signature signature = Signature.getInstance(access.getPublicKeySignatureAlgorithm());
            signature.initSign(key);
            signature.update(certificateRequestInfo);

            byte[] certificateRequestInfoSignature = signature.sign();

            DerOutputStream der3 = new DerOutputStream();
            der3.write(certificateRequestInfo);
            AlgorithmId.get(access.getPublicKeySignatureAlgorithm()).encode(der3);
            der3.putBitString(certificateRequestInfoSignature);

            DerOutputStream der4 = new DerOutputStream();
            der4.write((byte) 48, der3);
            
            byte[] csrDER = der4.toByteArray();

            // WHATNEXT? Where do I put this thing? I'm the CA anyways
            
            return true;
        } catch (IOException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(MyCode.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

}
