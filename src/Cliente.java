/**
 * Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:


The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.extension.*;






public class Cliente {


	public static String ipMaquina= "192.168.0.11";
	public static int Puerto = 8051;
	

	public static void main(String[] args) throws IOException {

		boolean ejecutar = true;
		Socket sock = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		String posicion = "41242028210441";
		String d = "AES";
		
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
		ArrayList codigos = new ArrayList();
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
						codigos.add(n[i]);
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
					java.security.cert.X509Certificate cert = cambiobytes();
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
				
				String[] imp = fromServer.split(meh);
				fromServer = imp[1];
				System.out.println(fromServer);

			
				try {
					byte[] decifrar = decifrarClaveSimetrica(DatatypeConverter.parseHexBinary(fromServer), codigos);
					String de = DatatypeConverter.printHexBinary(decifrar);
					
					
					KeyPairGenerator generadorKey = KeyPairGenerator.getInstance("RSA");
					generadorKey.initialize(1024, new SecureRandom());
					KeyPair keypair = generadorKey.generateKeyPair();
					
					byte[] dec = DatatypeConverter.parseHexBinary(posicion);
					
					
					byte[] cifrar = cifrarClaveSimetrica(dec, d, keypair.getPrivate())	;
					
					String comb = "ACT1:"+DatatypeConverter.printHexBinary(cifrar);
					
					Mac m = Mac.getInstance("HMACSHA1");
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
		// cierre el socket y la entrada estándar
		sock.close();
		stdIn.close();

	}

	@SuppressWarnings("depreciation")
	private static X509Certificate cambiobytes() throws NoSuchAlgorithmException {
		
	
		
		KeyPairGenerator generadorKey = KeyPairGenerator.getInstance("RSA");
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
	private static byte[] decifrarClaveSimetrica(byte[] a , ArrayList c) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		
		KeyPairGenerator generadorKey = KeyPairGenerator.getInstance("RSA");
		generadorKey.initialize(1024, new SecureRandom());
		KeyPair keypair = generadorKey.generateKeyPair();
		

		String sime = (String) "RSA";
		Cipher ci = Cipher.getInstance(sime);
		ci.init(2, keypair.getPrivate());
		return a;
		
		
	}
	private static byte[] cifrarClaveSimetrica(byte[] a, String sim, Key llave) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{

		
		String symetrico = "RSA";
		Cipher ci = Cipher.getInstance(symetrico);
		ci.init(1, llave);
		return ci.doFinal(a);
	}
	

}
