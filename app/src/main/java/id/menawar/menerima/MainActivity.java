/*
 * Copyright (c) 2016 Dawud Tan
 * All rights reserved.
 *
 * This code is licensed under the MIT License.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package id.menawar.menerima;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.Editable;
import android.text.TextWatcher;

import androidx.appcompat.app.AppCompatActivity;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.security.auth.x500.X500Principal;

import id.menawar.menerima.utility.PemUtils;

public class MainActivity extends AppCompatActivity {
    private CoordinatorLayout mCoordinatorLayout;
    private TextInputEditText alamatOfferee, penawaranElektronikPasal20UUITE2008, dwimalisasiRedaksiPenawaran, ttdOfferor, responOfferee, ttdOfferee, verifikasiTtdOfferee;
    private final ExecutorService es = Executors.newSingleThreadExecutor();
    private X509Certificate offereeCert;
    private X509Certificate offerorCert;
    private PrivateKey offerorKey;
    private SignerInformationVerifier siv;
    private SMIMESignedGenerator gen;
    private Signature signature;
    private MessageDigest digest, digestSignedAttr;
    private Format numberFormat;
    private HashMap parameters;
    private CMSAttributeTableGenerator sAttrGen;
    private static String KEY_NAME = "pasangan_kunci";
    private static String FIRST = "pertama-kali-pasang";
    private String uniqueID;

//    static {
//        System.loadLibrary("frida-gadget");
//    }

    private Locale getCurrentLocale(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return context.getResources().getConfiguration().getLocales().get(0);
        } else {
            return context.getResources().getConfiguration().locale;
        }
    }

    private String bigIntToString(BigInteger big) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            return ((android.icu.text.DecimalFormat) numberFormat).format(big);
        else
            return ((java.text.DecimalFormat) numberFormat).format(big);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Locale locale = getCurrentLocale(this);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            numberFormat = android.icu.text.NumberFormat.getInstance(locale);
        else
            numberFormat = java.text.NumberFormat.getInstance(locale);

        //AWAL inisialisasi
        inisialisasi();
        mCoordinatorLayout = findViewById(R.id.koordinatorLayout);
        alamatOfferee = findViewById(R.id.alamatOfferee);
        penawaranElektronikPasal20UUITE2008 = findViewById(R.id.penawaranElektronikPasal20UUITE2008);
        penawaranElektronikPasal20UUITE2008.requestFocus();
        sAttrGen = new DefaultSignedAttributeTableGenerator();

        parameters = new HashMap();
        parameters.put(CMSAttributeTableGenerator.CONTENT_TYPE, CMSObjectIdentifiers.data);
        parameters.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE));
        parameters.put(CMSAttributeTableGenerator.SIGNATURE_ALGORITHM_IDENTIFIER, new AlgorithmIdentifier(PKCSObjectIdentifiers.sha512WithRSAEncryption, DERNull.INSTANCE));

        try {
            digestSignedAttr = MessageDigest.getInstance("SHA512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        /*
          § 2-201. Formal Requirements; Statute of Frauds.
          (1) A contract for the sale of goods for the price of $5,000 or more is not enforceable
          by way of action or defense unless there is some record sufficient to indicate that
          a contract for sale has been made between the parties and signed by the party against
          which enforcement is sought or by the party's authorized agent or broker.
          A record is not insufficient because it omits or incorrectly states a term agreed upon
          but the contract is not enforceable under this subsection beyond the quantity of goods shown
          in the record.

          UCC § 2-201 (1)

          H. Gabriel, L. Rusch and A. Boss, The ABCs of the UCC (Revised) Article 2: Sales. Chicago, IL: ABA, Section of Business Law, 2004.
         */
        penawaranElektronikPasal20UUITE2008.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void afterTextChanged(Editable editable) {
                try {
                    dwimalisasiRedaksiPenawaran.setText(getDvimalString(editable.toString()));
                    ttdOfferor.setText(tandatangannyaOfferor(editable.toString()));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        dwimalisasiRedaksiPenawaran = findViewById(R.id.dwimalisasiRedaksiPenawaran);
        dwimalisasiRedaksiPenawaran.setText(getDvimalString(penawaranElektronikPasal20UUITE2008.getText().toString()));

        //BigInteger eksponenPenandatanganan = ((ASN1Integer) ((DLSequence) new ASN1InputStream(((DEROctetString) ((DLSequence) new ASN1InputStream(offerorKey.getEncoded()).readObject()).getObjectAt(2)).getOctets()).readObject()).getObjectAt(3)).getValue();

        ttdOfferor = findViewById(R.id.ttdOfferor);
        try {
            ttdOfferor.setText(tandatangannyaOfferor(penawaranElektronikPasal20UUITE2008.getText().toString()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        responOfferee = findViewById(R.id.responOfferee);
        TextInputEditText kunciVerifikasiOfferee = findViewById(R.id.kunciVerifikasiOfferee);

        try {
            kunciVerifikasiOfferee.setText(bigIntToString(((ASN1Integer) ((DLSequence) new ASN1InputStream(((DERBitString) ((DLSequence) ((DLSequence) ((DLSequence) new ASN1InputStream(offereeCert.getEncoded()).readObject()).getObjectAt(0)).getObjectAt(6)).getObjectAt(1)).getOctets()).readObject()).getObjectAt(0)).getPositiveValue()));
        } catch (IOException | CertificateEncodingException e) {
            e.printStackTrace();
        }

        ttdOfferee = findViewById(R.id.ttdOfferee);

        verifikasiTtdOfferee = findViewById(R.id.verifikasiTtdOfferee);
        //AKHIR inisialisasi

        findViewById(R.id.fab).setOnClickListener(view -> {
            try {
                formValidation();
                String redaksiPerikatan = penawaranElektronikPasal20UUITE2008.getText().toString();
                dwimalisasiRedaksiPenawaran.setText(getDvimalString(redaksiPerikatan));

                Future<MimeMultipart> pesan = CallSynchronous("redaksiPerikatan=" + URLEncoder.encode(redaksiPerikatan, "utf-8"), alamatOfferee.getText().toString());
                MimeMultipart body = pesan.get();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                body.getBodyPart(0).writeTo(baos);
                responOfferee.setText(new String(baos.toByteArray()));

                SignerInformation signerInformation = new SMIMESigned(body).getSignerInfos().getSigners().iterator().next();
                byte[] ttdnya = signerInformation.getSignature();

                ttdOfferee.setText(sig(ttdnya));
                offereeCert.checkValidity();
                boolean hasil = signerInformation.verify(siv);
                verifikasiTtdOfferee.setText(hasil ? "Pesan dari offeree utuh, tdk termodifikasi" : "termodifikasi");
                TampilkanPerubahanFragment.newInstance().show(getSupportFragmentManager(), "1");
            } catch (Exception ex) {
                Snackbar.make(mCoordinatorLayout, ex.getMessage(), Snackbar.LENGTH_LONG).show();
                ex.printStackTrace();
            }
        });
    }

    private String tandatangannyaOfferor(String redaksinya) throws Exception {
        StringBuilder redaksi = new StringBuilder("Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" +
                "Content-Transfer-Encoding: binary\r\n\r\n");
        redaksi.append("redaksiPerikatan=");
        redaksi.append(URLEncoder.encode(redaksinya, "utf-8"));//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
        digestSignedAttr.reset();
        byte[] digest = digestSignedAttr.digest(redaksi.toString().getBytes("UTF-8"));
        parameters.put(CMSAttributeTableGenerator.DIGEST, Arrays.clone(digest));
        AttributeTable signed = sAttrGen.getAttributes(Collections.unmodifiableMap(parameters));
        ASN1Set signedAttr = new DERSet(signed.toASN1EncodableVector());
        byte[] teks = signedAttr.getEncoded(ASN1Encoding.DER);//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
        signature.update(teks, 0, teks.length);
        byte[] sig = signature.sign();
        return sig(sig);
    }

    private String sig(byte[] sig) {
        return bigIntToString(new BigInteger(1, sig));
    }

    private void formValidation() throws Exception {
        //validasi form
        if (alamatOfferee.getText().length() <= 0) {
            alamatOfferee.requestFocus();
            throw new Exception("Alamat Penjual belum ditentukan");
        }
    }

    public Future<MimeMultipart> CallSynchronous(
            final String content,
            final String alamatPenjual) {
        return es.submit(() -> {
            MimeBodyPart aPart = new MimeBodyPart();
            aPart.setContent(content, "application/x-www-form-urlencoded; charset=UTF-8");
            aPart.setHeader("Content-Transfer-Encoding", "binary");
            MimeMultipart aSignedData = gen.generate(aPart);
            MimeBodyPart output = new MimeBodyPart();
            output.setContent(aSignedData);
            output.setHeader("Content-Type", aSignedData.getContentType());
            String from = "dawud_tan@merahputih.id";

            URL urlPenjual = new URL(alamatPenjual);
            InetAddress alamatIPPenjual = InetAddress.getByName(urlPenjual.getHost());
            if (alamatIPPenjual.isSiteLocalAddress())
                throw new RuntimeException("Alamat IP Penjual privat, tidak bisa dicapai.");
            HttpURLConnection con = (HttpURLConnection) urlPenjual.openConnection();
            con.setRequestMethod("POST");
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setRequestProperty("Connection", "close");
            con.setRequestProperty("From", from);
            con.setRequestProperty("AS2-Version", "1.1");
            con.setRequestProperty("AS2-From", uniqueID);
            con.setRequestProperty("AS2-To", "mendelsontestAS2");
            con.setRequestProperty("Subject", "https://s.id/tr1-2");
            con.setRequestProperty("Message-Id", new StringBuilder("<github-dawud-tan-").append(new SimpleDateFormat("ddMMyyyyHHmmssZ", getCurrentLocale(this)).format(new Date())).append("-").append(new Random().nextLong()).append("@mycompanyAS2_mendelsontestAS2>").toString());
            con.setRequestProperty("Disposition-Notification-To", from);//ask receiving UA, to issue an MDN receipt
            con.setRequestProperty("Disposition-Notification-Options",
                    "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha512");
            con.setRequestProperty("Content-Type", output.getContentType().replace("\r\n\r\n", " ").replace("\r\n", " "));
            con.setRequestProperty("Accept", "multipart/signed");
            InputStream in = output.getInputStream();
            ByteArrayOutputStream temp = new ByteArrayOutputStream();
            final byte[] b = new byte[8192];
            for (int r; (r = in.read(b)) != -1; ) {
                temp.write(b, 0, r);
            }
            OutputStream os = con.getOutputStream();
            os.write(temp.toByteArray());
            os.flush();
            os.close();
            return (MimeMultipart) con.getContent();
        });
    }

    private void inisialisasi() {
        InputStream masukan = MainActivity.class.getResourceAsStream("/offeree.crt");//untuk kunci publik penjual
        try {
            offereeCert = PemUtils.decodeCertificate(masukan);
            Objects.requireNonNull(masukan).close();
            masukan = null;

            digest = MessageDigest.getInstance("SHA512");

            SharedPreferences sharedPref = getPreferences(Context.MODE_PRIVATE);
            if (sharedPref.getBoolean(FIRST, true)) {
                KeyPairGenerator mKeyPairGenerator = keyPairGenerator();
                mKeyPairGenerator.initialize(getParams());
                mKeyPairGenerator.generateKeyPair();

                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);
                offerorCert = (X509Certificate) keyStore.getCertificate(KEY_NAME);

                uniqueID = UUID.randomUUID().toString();

                sharedPref.edit().putString("uniqueID", uniqueID).commit();
                String sertifikat = new String(Base64.encode(offerorCert.getEncoded()), "utf8");
                es.submit(() -> {
                    try {
                        String pUID = URLEncoder.encode(uniqueID, "utf-8");
                        String pSert = URLEncoder.encode(sertifikat, "utf-8");
                        String urlParameters = "guid=" + pUID + "&kunciPublik=" + pSert;
                        byte[] postData = urlParameters.getBytes("utf8");

                        String request = getString(R.string.tambahSertifikat);
                        URL url = new URL(request);
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setDoOutput(true);
                        conn.setDoInput(false);
                        conn.setRequestMethod("POST");
                        conn.setRequestProperty("Connection", "close");
                        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                        conn.setRequestProperty("charset", "utf-8");
                        DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
                        wr.write(postData);
                        wr.flush();
                        wr.close();
                        conn.getResponseCode();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }).get();
                sharedPref.edit().putBoolean(FIRST, false).apply();
            } else {
                uniqueID = sharedPref.getString("uniqueID", "--heu--");
            }

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            offerorCert = (X509Certificate) keyStore.getCertificate(KEY_NAME);
            offerorKey = (PrivateKey) keyStore.getKey(KEY_NAME, null);

            siv = new JcaSimpleSignerInfoVerifierBuilder().build(offereeCert.getPublicKey());
            signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(offerorKey);

            SignerInfoGenerator signer = new JcaSimpleSignerInfoGeneratorBuilder()
                    .build("SHA512withRSA", offerorKey, offerorCert);

            gen = new SMIMESignedGenerator();
            gen.addSignerInfoGenerator(signer);
            //secara default, content-transfer-encoding base64
            gen.setContentTransferEncoding("binary");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getDvimalString(String asal) {
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < asal.length(); j++) {
            String a = asal.substring(j, j + 1);
            sb.append(a);
            sb.append(": ");
            for (byte b : a.getBytes()) {
                sb.append(Integer.toBinaryString((b & 0xFF) + 0x100).substring(1));
            }
            sb.append("\r\n");
        }
        return sb.toString();
    }

    public boolean daringKah() {
        ConnectivityManager manajerKonektivitas = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo jaringanAktif = manajerKonektivitas.getActiveNetworkInfo();
        return jaringanAktif != null && (jaringanAktif.getType() == ConnectivityManager.TYPE_MOBILE || jaringanAktif.getType() == ConnectivityManager.TYPE_WIFI);
    }

    private KeyPairGenerator keyPairGenerator() throws NoSuchProviderException, NoSuchAlgorithmException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        else
            return KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    }

    private AlgorithmParameterSpec getParams() {
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(1, Calendar.YEAR);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && Build.VERSION.SDK_INT <= Build.VERSION_CODES.LOLLIPOP_MR1) {
            return new KeyPairGeneratorSpec.Builder(this)
                    .setAlias(KEY_NAME)
                    .setSubject(new X500Principal("CN=" + KEY_NAME))
                    .setSerialNumber(BigInteger.valueOf(1337))
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
            return new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_SIGN)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setCertificateSerialNumber(BigInteger.valueOf(1337))
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(false)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA512)
                    .build();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_SIGN)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setCertificateSerialNumber(BigInteger.valueOf(1337))
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(false)
                    .setUserConfirmationRequired(false)
                    .setUserAuthenticationValidWhileOnBody(false)
                    .setUnlockedDeviceRequired(false)
                    .setUserPresenceRequired(false)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA512)
                    .build();
        } else {
            return new KeyPairGeneratorSpec.Builder(this)
                    .setAlias(KEY_NAME)
                    .setSubject(new X500Principal("CN=" + KEY_NAME))
                    .setSerialNumber(BigInteger.valueOf(1337))
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        }
    }

}