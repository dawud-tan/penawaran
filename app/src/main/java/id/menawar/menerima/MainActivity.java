package id.menawar.menerima;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;

import androidx.appcompat.app.AppCompatActivity;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import id.menawar.menerima.utility.PemUtils;

/**
 * Created by dawud_tan on 11/11/16.
 */
public class MainActivity extends AppCompatActivity {
    private CoordinatorLayout mCoordinatorLayout;
    private TextInputEditText alamatOfferee, kontrakElektronikPasal18UUITE2008, dwimalisasiRedaksiKontrak, kunciPenandatangananOfferor, ttdOfferor, responOfferee, kunciVerifikasiOfferee, ttdOfferee, verifikasiTtdOfferee;
    private ExecutorService es = Executors.newSingleThreadExecutor();
    private X509Certificate offereeCert;
    private X509Certificate offerorCert;
    private PrivateKey offerorKey;
    private SignerInformationVerifier siv;
    private SMIMESignedGenerator gen;
    private Signature signature;
    private MessageDigest digest;


    private static BigInteger toBigInt(byte[] arr) {
        byte[] rev = new byte[arr.length + 1];
        for (int i = 0, j = arr.length; j > 0; i++, j--)
            rev[j] = arr[i];
        return new BigInteger(1, rev);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //AWAL inisialisasi
        inisialisasi();
        mCoordinatorLayout = findViewById(R.id.koordinatorLayout);
        alamatOfferee = findViewById(R.id.alamatOfferee);
        kontrakElektronikPasal18UUITE2008 = findViewById(R.id.kontrakElektronikPasal18UUITE2008);
        kontrakElektronikPasal18UUITE2008.requestFocus();
        /**
         * § 2-201. Formal Requirements; Statute of Frauds.
         * (1) A contract for the sale of goods for the price of $5,000 or more is not enforceable
         * by way of action or defense unless there is some record sufficient to indicate that
         * a contract for sale has been made between the parties and signed by the party against
         * which enforcement is sought or by the party's authorized agent or broker.
         * A record is not insufficient because it omits or incorrectly states a term agreed upon
         * but the contract is not enforceable under this subsection beyond the quantity of goods shown
         * in the record.
         *
         * UCC § 2-201 (1)
         *
         * H. Gabriel, L. Rusch and A. Boss, The ABCs of the UCC (Revised) Article 2: Sales. Chicago, IL: ABA, Section of Business Law, 2004.
         */
        kontrakElektronikPasal18UUITE2008.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {

            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {

            }

            @Override
            public void afterTextChanged(Editable editable) {
                try {
                    String redaksi = editable.toString();//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
                    byte[] teks = redaksi.getBytes("UTF-8");//"Electronically Stored Information, electronic discovery, Federal Rules of Civil Procedure
                    dwimalisasiRedaksiKontrak.setText(getBinaryString(redaksi));
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

                    ttdOfferor.setText("R.X: " + toBigInt(rX).toString() + "\nR.Y: " + toBigInt(rY).toString() + "\nS: " + toBigInt(S).toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        dwimalisasiRedaksiKontrak = findViewById(R.id.dwimalisasiRedaksiKontrak);
        dwimalisasiRedaksiKontrak.setText(getBinaryString(kontrakElektronikPasal18UUITE2008.getText().toString()));

        kunciPenandatangananOfferor = findViewById(R.id.kunciPenandatangananOfferor);
        try {
            DLTaggedObject priv = (DLTaggedObject) ((DLSequence) new ASN1InputStream(offerorKey.getEncoded()).readObject()).getObjectAt(3);
            digest.reset();
            byte[] h = digest.digest(priv.getEncoded());
            byte[] s = new byte[32];
            System.arraycopy(h, 0, s, 0, 32);
            s[0] &= 0xF8;
            s[31] &= 0x7F;
            s[31] |= 0x40;
            kunciPenandatangananOfferor.setText(toBigInt(s).toString());//kunci pribadi bisa berumur panjang,
            // compromised setelah dpakai membuat ttd, ttd lama yang sudah terjadi tetap verified kan.
            // beda dengan kunci publik utk enkripsi

            //kunci pribadi di enkripsi dengan PBKDF2, password based key derivation function
            //atau VERIFIKASI SIGNATURE


        } catch (IOException e) {
            e.printStackTrace();
        }

        ttdOfferor = findViewById(R.id.ttdOfferor);
        try {
            byte[] larikRedaksiKontrak = kontrakElektronikPasal18UUITE2008.getText().toString().getBytes("UTF-8");
            signature.update(larikRedaksiKontrak);

            byte[] sig = signature.sign();

            byte[] R = org.bouncycastle.util.Arrays.copyOfRange(sig, 0, 32);//Decode the first half as a point R
            Ed25519.PointAffine pAra = new Ed25519.PointAffine();
            Ed25519.decodePointVar(R, 0, false, pAra);

            byte[] rX = new byte[Ed25519.PUBLIC_KEY_SIZE];
            byte[] rY = new byte[Ed25519.PUBLIC_KEY_SIZE];
            X25519Field.encode(pAra.y, rY, 0);
            X25519Field.encode(pAra.x, rX, 0);

            byte[] S = org.bouncycastle.util.Arrays.copyOfRange(sig, 32, 64);//Decode the second half as an integer S, in the range 0 <= s < L

            ttdOfferor.setText("R.X: " + toBigInt(rX).toString() + "\nR.Y: " + toBigInt(rY).toString() + "\nS: " + toBigInt(S).toString());

        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        responOfferee = findViewById(R.id.responOfferee);
        kunciVerifikasiOfferee = findViewById(R.id.kunciVerifikasiOfferee);

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

            kunciVerifikasiOfferee.setText("Koordinat X: " + toBigInt(rX) + "\nKoordinat Y:" + toBigInt(rY));
        } catch (IOException e) {
            e.printStackTrace();
        }

        ttdOfferee = findViewById(R.id.ttdOfferee);

        verifikasiTtdOfferee = findViewById(R.id.verifikasiTtdOfferee);
        //AKHIR inisialisasi

        findViewById(R.id.fab).setOnClickListener(view -> {
            try {
                formValidation();
                String redaksiKontrak = kontrakElektronikPasal18UUITE2008.getText().toString();
                dwimalisasiRedaksiKontrak.setText(getBinaryString(redaksiKontrak));
                signature.update(redaksiKontrak.getBytes("utf-8"));
                byte[] sig = signature.sign();
                byte[] Rr = org.bouncycastle.util.Arrays.copyOfRange(sig, 0, 32);//Decode the first half as a point R
                Ed25519.PointAffine pAr = new Ed25519.PointAffine();
                Ed25519.decodePointVar(Rr, 0, false, pAr);

                byte[] rXr = new byte[Ed25519.PUBLIC_KEY_SIZE];
                byte[] rYr = new byte[Ed25519.PUBLIC_KEY_SIZE];
                X25519Field.encode(pAr.y, rYr, 0);
                X25519Field.encode(pAr.x, rXr, 0);

                byte[] Sr = org.bouncycastle.util.Arrays.copyOfRange(sig, 32, 64);//Decode the second half as an integer S, in the range 0 <= s < L

                ttdOfferor.setText("R.X: " + toBigInt(rXr).toString() + "\nR.Y: " + toBigInt(rYr).toString() + "\nS: " + toBigInt(Sr).toString());

                Future<MimeMultipart> pesan = CallSynchronous("redaksiKontrak=" + URLEncoder.encode(redaksiKontrak, "utf-8"), alamatOfferee.getText().toString());
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

                ttdOfferee.setText("R.X: " + toBigInt(rX).toString() + "\nR.Y: " + toBigInt(rY).toString() + "\nS: " + toBigInt(S).toString());
                offereeCert.checkValidity();
                boolean hasil = signerInformation.verify(siv);
                verifikasiTtdOfferee.setText(hasil ? "Pesan dari offeree utuh, tdk termodifikasi" : "termodifikasi");
            } catch (Exception ex) {
                Snackbar.make(mCoordinatorLayout, ex.getMessage(), Snackbar.LENGTH_LONG).show();
                ex.printStackTrace();
            }
        });
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

            HttpURLConnection con = (HttpURLConnection) new URL(alamatPenjual).openConnection();
            con.setRequestMethod("POST");
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setRequestProperty("Connection", "close");
            con.setRequestProperty("From", from);
            con.setRequestProperty("AS2-Version", "1.1");
            con.setRequestProperty("AS2-From", "mycompanyAS2");
            con.setRequestProperty("AS2-To", "mendelsontestAS2");
            con.setRequestProperty("Subject", "https://s.id/2aYby");
            con.setRequestProperty("Message-Id", "<github-dawud-tan-" + new SimpleDateFormat("ddMMyyyyHHmmssZ").format(new Date()) + "-" + new Random().nextLong() + "@mycompanyAS2_mendelsontestAS2>");
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
            digest = MessageDigest.getInstance("sha512", "BC25519");
            offereeCert = PemUtils.decodeCertificate(masukan);
            masukan = MainActivity.class.getResourceAsStream("/offeror.crt");//untuk kunci publik pembeli
            offerorCert = PemUtils.decodeCertificate(masukan);
            masukan = MainActivity.class.getResourceAsStream("/offeror.key");//untuk kunci penandatangan pembeli
            offerorKey = PemUtils.decodePrivateKey(masukan, "ED25519");
            masukan.close();
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

        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private String getBinaryString(String asal) {
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
}