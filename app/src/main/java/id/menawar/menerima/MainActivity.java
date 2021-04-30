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
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;

import androidx.appcompat.app.AppCompatActivity;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
import org.bouncycastle.math.ec.rfc7748.X25519Field;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

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
    Format numberFormat;
    HashMap parameters;
    CMSAttributeTableGenerator sAttrGen;
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

    private String toBigInt(byte[] arr) {
        byte[] rev = new byte[arr.length + 1];
        for (int i = 0, j = arr.length; j > 0; i++, j--) {
            rev[j] = arr[i];
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            return ((android.icu.text.DecimalFormat) numberFormat).format(new BigInteger(1, rev));
        else
            return ((java.text.DecimalFormat) numberFormat).format(new BigInteger(1, rev));
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
        parameters.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
        parameters.put(CMSAttributeTableGenerator.SIGNATURE_ALGORITHM_IDENTIFIER, new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
        try {
            digestSignedAttr = MessageDigest.getInstance("sha512", "BC25519");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
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

        TextInputEditText kunciPenandatangananOfferor = findViewById(R.id.kunciPenandatangananOfferor);
        try {
            DLTaggedObject priv = (DLTaggedObject) ((DLSequence) new ASN1InputStream(offerorKey.getEncoded()).readObject()).getObjectAt(3);
            digest.reset();
            byte[] h = digest.digest(priv.getEncoded());
            byte[] s = new byte[32];
            System.arraycopy(h, 0, s, 0, 32);
            s[0] &= 0xF8;
            s[31] &= 0x7F;
            s[31] |= 0x40;
            kunciPenandatangananOfferor.setText(toBigInt(s));
            // kunci penandatanganan bisa berumur panjang,
            // compromised setelah dipakai membuat ttd, ttd lama yang sudah terjadi tetap terverifikasi kan.
            // beda dengan kunci publik untuk enkripsi

            // Sumber:
            // N. Borisov, I. Goldberg dan E. Brewer, "Off-the-Record Communication, or, Why Not
            // To Use PGP", in Proceedings of the 2004 ACM Workshop on Privacy in the Electronic
            // Society - WPES '04, Yours Truly DC, West End, Washington DC, 2004, hal. 77-84.
            // Tersedia: http://dl.acm.org/doi/abs/10.1145/1029179.1029200

            //Jum'at, 29 Oktober 2004
            //03.00-03.25 WITA

            //Yours Truly DC (Place ID: ChIJ13PA3123t4kRzeDA41CDqCI)
            //jalan New Hampshire 1143 barat laut, West End, Washington, DC, 20037, Amerika Serikat

            //kunci pribadi di enkripsi dengan PBKDF2, password based key derivation function
            //atau VERIFIKASI SIGNATURE

        } catch (IOException e) {
            e.printStackTrace();
        }

        ttdOfferor = findViewById(R.id.ttdOfferor);
        try {
            ttdOfferor.setText(tandatangannyaOfferor(penawaranElektronikPasal20UUITE2008.getText().toString()));
        } catch (SignatureException | IOException e) {
            e.printStackTrace();
        }

        responOfferee = findViewById(R.id.responOfferee);
        TextInputEditText kunciVerifikasiOfferee = findViewById(R.id.kunciVerifikasiOfferee);

        try {
            DERBitString dbs = (DERBitString) ((DLSequence) new ASN1InputStream(offereeCert.getPublicKey().getEncoded()).readObject()).getObjectAt(1);
            byte[] oktet = dbs.getOctets();//cara mengubah ke KOORDINAT y

            Ed25519.PointAffine pA = new Ed25519.PointAffine();
            Ed25519.decodePointVar(oktet, 0, false, pA);

            //ubah kunci publik jadi koordinat X dan Y
            byte[] rY = new byte[Ed25519.PUBLIC_KEY_SIZE];
            byte[] rX = new byte[Ed25519.PUBLIC_KEY_SIZE];
            X25519Field.encode(pA.y, rY, 0);
            X25519Field.encode(pA.x, rX, 0);

            kunciVerifikasiOfferee.setText(new StringBuilder("Koordinat X: ").append(toBigInt(rX)).append("\nKoordinat Y:").append(toBigInt(rY)).toString());
        } catch (IOException e) {
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

                byte[] R = org.bouncycastle.util.Arrays.copyOfRange(ttdnya, 0, 32);//Decode the first half as a point R
                Ed25519.PointAffine pAra = new Ed25519.PointAffine();
                Ed25519.decodePointVar(R, 0, false, pAra);

                byte[] rX = new byte[Ed25519.PUBLIC_KEY_SIZE];
                byte[] rY = new byte[Ed25519.PUBLIC_KEY_SIZE];
                X25519Field.encode(pAra.y, rY, 0);
                X25519Field.encode(pAra.x, rX, 0);

                byte[] S = org.bouncycastle.util.Arrays.copyOfRange(ttdnya, 32, 64);//Decode the second half as an integer S, in the range 0 <= s < L

                ttdOfferee.setText(new StringBuilder("R.X: ").append(toBigInt(rX)).append("\nR.Y: ").append(toBigInt(rY)).append("\nS: ").append(toBigInt(S)).toString());
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

    private String tandatangannyaOfferor(String redaksinya) throws IOException, SignatureException {
        StringBuilder redaksi = new StringBuilder("Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n" +
                "Content-Transfer-Encoding: binary\r\n\r\n");
        redaksi.append("redaksiPerikatan=");
        redaksi.append(URLEncoder.encode(redaksinya, "utf-8"));//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
        digestSignedAttr.reset();
        byte[] digest = digestSignedAttr.digest(redaksi.toString().getBytes(StandardCharsets.UTF_8));
        parameters.put(CMSAttributeTableGenerator.DIGEST, Arrays.clone(digest));
        AttributeTable signed = sAttrGen.getAttributes(Collections.unmodifiableMap(parameters));
        ASN1Set signedAttr = new DERSet(signed.toASN1EncodableVector());
        byte[] teks = signedAttr.getEncoded(ASN1Encoding.DER);//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
        signature.update(teks);
        byte[] sig = signature.sign();
        byte[] R = org.bouncycastle.util.Arrays.copyOfRange(sig, 0, 32);//Decode the first half as a point R
        Ed25519.PointAffine pAra = new Ed25519.PointAffine();
        Ed25519.decodePointVar(R, 0, false, pAra);
        byte[] rX = new byte[Ed25519.PUBLIC_KEY_SIZE];
        byte[] rY = new byte[Ed25519.PUBLIC_KEY_SIZE];
        X25519Field.encode(pAra.y, rY, 0);
        X25519Field.encode(pAra.x, rX, 0);
        byte[] S = org.bouncycastle.util.Arrays.copyOfRange(sig, 32, 64);//Decode the second half as an integer S, in the range 0 <= s < L
        return new StringBuilder("R.X: ").append(toBigInt(rX))
                .append("\nR.Y: ").append(toBigInt(rY))
                .append("\nS: ").append(toBigInt(S)).toString();
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
            offerorCert.checkValidity();
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
            con.setRequestProperty("AS2-From", "mycompanyAS2");
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
            //KeyInfo.isInsideSecureHardware
            //KeyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware()
            digest = MessageDigest.getInstance("sha512", "BC25519");
            offereeCert = PemUtils.decodeCertificate(masukan);
            masukan = MainActivity.class.getResourceAsStream("/offeror.crt");//untuk kunci publik pembeli
            offerorCert = PemUtils.decodeCertificate(masukan);
            masukan = MainActivity.class.getResourceAsStream("/offeror.key");//untuk kunci penandatangan pembeli
            offerorKey = PemUtils.decodePrivateKey(masukan, "ED25519");
            Objects.requireNonNull(masukan).close();
            masukan = null;

            siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC25519").build(offereeCert.getPublicKey());
            signature = Signature.getInstance("ed25519", "BC25519");
            signature.initSign(offerorKey);

            SignerInfoGenerator signer = new JcaSimpleSignerInfoGeneratorBuilder()
                    .setProvider("BC25519")
                    .build("ed25519", offerorKey, offerorCert);

            gen = new SMIMESignedGenerator();
            gen.addSignerInfoGenerator(signer);
            //secara default, content-transfer-encoding base64
            gen.setContentTransferEncoding("binary");

        } catch (IOException | CertificateException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException | OperatorCreationException | InvalidKeyException e) {
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
}