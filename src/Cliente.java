/**
 * Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:


The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Cliente {

	public static String ipMaquina= "192.168.56.1";
	public static int Puerto = 8051;
	

	public static void main(String[] args) throws IOException {

		boolean ejecutar = true;
		Socket sock = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		String posicion = "41242028210441";
		ArrayList<String> codigos = new ArrayList<>();

		try {
			sock = new Socket(ipMaquina, Puerto);
			escritor = new PrintWriter(sock.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(
					sock.getInputStream()));
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
		BufferedReader stdIn = new BufferedReader(
				new InputStreamReader(System.in));
		int estado = 0;
		String fromServer;
		String fromUser;
		while (ejecutar) {


			if (estado==0){
				System.out.print("Escriba HOLA:");
				fromUser = stdIn.readLine();
				if (fromUser != null && !fromUser.equals("-1")) {
					System.out.println("Cliente: " + fromUser);

					escritor.println(fromUser);
				}
				estado++;

			}
			else if(estado==1)
			{
				System.out.print("Escriba el algoritmo a usar: ");
				fromUser = stdIn.readLine();
				if (fromUser != null && !fromUser.equals("-1")) {
					System.out.println("Cliente: " + fromUser);
					escritor.println(fromUser);
					String[]n = fromUser.split(":");
					for(int i = 0; i<n.length;i++)
					{
						codigos.add(n[i]); System.out.println(n[i]);
					}

				}
				estado++;

			}
			else if(estado == 2)
			{
				System.out.print(" (CERTCLNT): ");
				fromUser = stdIn.readLine();
				if (fromUser != null && !fromUser.equals("-1")) {
					System.out.println("Cliente: "+ fromUser);
					escritor.println(fromUser);
				}
				System.out.println("Ahora se enviara su info en bytes ");

				try {
					java.security.cert.X509Certificate cert = cambiobytes(codigos);
					byte[] mybyte = cert.getEncoded();

					sock.getOutputStream().write(mybyte);
					sock.getOutputStream().flush();

				} catch (CertificateEncodingException | NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				estado++;
				fromServer= lector.readLine();
				fromServer= lector.readLine();
				fromServer= lector.readLine();
				fromServer= lector.readLine();
				fromServer= lector.readLine();


			}
			else if(estado==3)
			{
				escritor.println("ESTADO:OK");
				estado ++;
			}
			else if(estado==4)
			{
				String meh = "INICIO:";
				fromServer = lector.readLine();

				while(!fromServer.contains(meh))
				{
					fromServer = lector.readLine();
				}

				String[] imp = fromServer.split(":");
				fromServer = imp[1];
				System.out.println(fromServer);


				try {
					System.out.println("llegó");
					byte[] decifrar = decifrarClaveSimetrica(DatatypeConverter.parseHexBinary(fromServer), codigos);
					String de = DatatypeConverter.printHexBinary(decifrar);

					KeyPairGenerator generadorKey = KeyPairGenerator.getInstance((String) codigos.get(2));
					generadorKey.initialize(1024, new SecureRandom());
					KeyPair keypair = generadorKey.generateKeyPair();

					byte[] dec = DatatypeConverter.parseHexBinary(posicion);

					String d = codigos.get(1);

					byte[] cifrar = cifrarClaveSimetrica(dec, d, keypair.getPrivate(), codigos)	;

					String comb = "ACT1:"+DatatypeConverter.printHexBinary(cifrar);

					Mac m = Mac.getInstance((String) codigos.get(3));
					m.init(keypair.getPublic());
					byte[] bytes = m.doFinal(cifrar);
					String enviar = DatatypeConverter.printHexBinary(decifrar);
					escritor.println(comb);
					escritor.println(enviar);



				} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
						| IllegalBlockSizeException | BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}
		//  ALGORITMOS:AES:RSA:HMACSHA1
		escritor.close();
		lector.close();
		sock.close();
		stdIn.close();

	}

	private static X509Certificate cambiobytes(ArrayList<String> c) throws NoSuchAlgorithmException {
KeyPairGenerator generadorKey = KeyPairGenerator.getInstance(c.get(2));
		generadorKey.initialize(1024, new SecureRandom());
		KeyPair keypair = generadorKey.generateKeyPair();


		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keypair.getPublic().getEncoded());
		BigInteger a = BigInteger.valueOf(new Long(123456723));
		X500Name nombre = new X500Name("CN=Cliente");
		Date antes = new Date(System.currentTimeMillis());
		Date Despues = new Date(System.currentTimeMillis()+(1000L*3600*24*365*100));
		X500Name nombre2 = new X500Name("CN=Servidor");
		X509v3CertificateBuilder myX509v3CertBuilder = new X509v3CertificateBuilder(nombre, a, antes, Despues, nombre2, publicKeyInfo);


		try {
			ContentSigner signer;
			signer = new JcaContentSignerBuilder("Sha256withRSA").build(keypair.getPrivate());
			X509CertificateHolder certHolder = myX509v3CertBuilder.build(signer);
			X509Certificate cert = (new JcaX509CertificateConverter()).getCertificate(certHolder);
			return cert;

		} catch (CertificateException | OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;




	}
	private static byte[] decifrarClaveSimetrica(byte[] a , ArrayList<String> c) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{

		KeyPairGenerator generadorKey = KeyPairGenerator.getInstance(c.get(2));
		generadorKey.initialize(1024, new SecureRandom());
		KeyPair keypair = generadorKey.generateKeyPair();
		Cipher ci = Cipher.getInstance(c.get(2));
		ci.init(2, keypair.getPrivate());
		return a;


	}
	private static byte[] cifrarClaveSimetrica(byte[] a, String sim, Key llave, ArrayList<String> c) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher ci = Cipher.getInstance(c.get(2));
		ci.init(1, llave);
		return ci.doFinal(a);
	}


}
